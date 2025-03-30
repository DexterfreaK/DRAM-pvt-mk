#include <llvm/IR/Function.h>
#include <llvm/IR/PassManager.h>
#include <llvm/Pass.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Support/Casting.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Passes/PassPlugin.h>
#include <llvm/IR/GlobalVariable.h>
#include <llvm/IR/TypeFinder.h>
#include <llvm/IR/Type.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/Support/CommandLine.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <map>
#include <vector>

namespace llvm {

// Command line option for CSV file path
static cl::opt<std::string> MapConfigFile("map-config",
                                        cl::desc("CSV file with map ID to map name mappings"),
                                        cl::value_desc("filename"));

class CustomModulePass : public PassInfoMixin<CustomModulePass> {
private:
    // Map to store ID -> MapName from CSV
    std::map<int, std::string> mapIdToName;

public:
    PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM) {
        // 1) Create struct.bpf_map_def type
        StructType *bpfMapDefType = StructType::create(
            M.getContext(),
            {
                Type::getInt32Ty(M.getContext()), // type
                Type::getInt32Ty(M.getContext()), // key_size
                Type::getInt32Ty(M.getContext()), // value_size
                Type::getInt32Ty(M.getContext()), // max_entries
                Type::getInt32Ty(M.getContext()), // map_flags
                Type::getInt32Ty(M.getContext()), // pinning
                Type::getInt32Ty(M.getContext())  // inner_map_fd
            },
            "struct.bpf_map_def"
        );

        // Create a global variable to ensure the struct type shows up in IR
        Constant* zeroInit = ConstantAggregateZero::get(bpfMapDefType);
        new GlobalVariable(M, bpfMapDefType, false, GlobalValue::ExternalLinkage, 
                          zeroInit, "bpf_map_def_placeholder_and_it_is_completely_useless_stuff_just_to_ensure_that_struct_gets_defined");

        // 2) Read map IDs and names from CSV file
        if (!MapConfigFile.empty()) {
            readMapConfig(MapConfigFile);
        } else {
            errs() << "Warning: No map configuration file provided\n";
            return PreservedAnalyses::none();
        }

        // 4) Remove existing global definitions for map names in our CSV
        std::vector<GlobalVariable*> globalsToRemove;
        for (auto &GV : M.globals()) {
            for (const auto &entry : mapIdToName) {
                if (GV.getName() == entry.second) {
                    globalsToRemove.push_back(&GV);
                    break;
                }
            }
        }
        
        // Actually remove the globals
        for (auto *GV : globalsToRemove) {
            GV->eraseFromParent();
        }

        // Create new global definitions for each map
        createMapDefinitions(M, bpfMapDefType);

        // 3) Transform bpf_map_lookup_elem calls
        transformMapLookups(M);

        return PreservedAnalyses::none();
    }

private:
    void readMapConfig(const std::string &filename) {
        std::ifstream file(filename);
        
        if (!file.is_open()) {
            errs() << "Error: Cannot open map config file: " << filename << "\n";
            return;
        }

        std::string line;
        while (std::getline(file, line)) {
            std::istringstream iss(line);
            std::string idStr, mapName;
            
            if (std::getline(iss, idStr, ',') && std::getline(iss, mapName)) {
                // Trim whitespace
                mapName.erase(0, mapName.find_first_not_of(" \t"));
                mapName.erase(mapName.find_last_not_of(" \t") + 1);
                
                try {
                    int id = std::stoi(idStr);
                    mapIdToName[id] = mapName;
                    errs() << "Loaded map config: ID " << id << " -> " << mapName << "\n";
                } catch (const std::exception &e) {
                    errs() << "Error parsing map ID: " << idStr << "\n";
                }
            }
        }
    }

    void createMapDefinitions(Module &M, StructType *bpfMapDefType) {
        for (const auto &entry : mapIdToName) {
            int mapId = entry.first;
            std::string mapName = entry.second;

            // Create external global variable (no initializer)
            GlobalVariable *gv = new GlobalVariable(
                M,                            // Module
                bpfMapDefType,                // Type
                false,                        // isConstant
                GlobalValue::ExternalLinkage, // Linkage
                nullptr,                      // Initializer (nullptr for external)
                mapName                       // Name
            );
            
            // Set section to ".maps" as in the original code
            // gv->setSection(".maps");
            gv->setAlignment(Align(8));
        }
    }

    void transformMapLookups(Module &M) {
        // Find all calls to bpf_map_lookup_elem
        std::vector<std::pair<CallInst*,std::string>> CallsToReplace;
        for (auto &F : M) {
            for (auto &BB : F) {
                for (auto &I : BB) {
                    if (CallInst *CI = dyn_cast<CallInst>(&I)) {
                        if (Function *CalledF = CI->getCalledFunction()) {
                            if (CalledF->getName() == "bpf_map_lookup_elem.toreplace") {
                                CallsToReplace.push_back({CI,"bpf_map_lookup_elem"});
                            }
                            if (CalledF->getName() == "bpf_map_delete_elem.toreplace") {
                                CallsToReplace.push_back({CI,"bpf_map_delete_elem"});
                            }
                            if (CalledF->getName() == "bpf_map_update_elem.toreplace") {
                                CallsToReplace.push_back({CI,"bpf_map_update_elem"});
                            }
                        }
                    }
                }
            }
        }

        // Now replace each call
        for (auto &i : CallsToReplace) {
            replaceMapLookupDelete(i.first, M, i.second, (i.second == "bpf_map_update_elem"));
        }

    }

    void replaceMapLookupDelete(CallInst *oldCall, Module &M, std::string func_name, bool is_update_func) {
        IRBuilder<> Builder(oldCall);
        
        // Get the map ID from the first argument
        Value *mapIdArg = oldCall->getArgOperand(0);
        Value *keyArg = oldCall->getArgOperand(1);
        
        // If it's a constant, we can determine which map it's accessing
        if (ConstantInt *CI = dyn_cast<ConstantInt>(mapIdArg)) {
            int mapId = CI->getSExtValue();
            errs() << "Found map lookup with ID: " << mapId << "\n";
            
            // Find if we have a name for this ID
            auto it = mapIdToName.find(mapId);
            if (it != mapIdToName.end()) {
                errs() << "  Mapped to map name: " << it->second << "\n";

                std::string mapName = it->second;

                // Get the map global variable
                GlobalVariable *mapGV = M.getGlobalVariable(mapName);
                if (!mapGV) {
                    errs() << "  Error: Map global variable not found: " << mapName << "\n";
                    return;
                }

                // 1. Cast map global variable to i8*
                Value *mapPtr = Builder.CreateBitCast(mapGV, Type::getInt8PtrTy(M.getContext()), mapName + "_ptr");

                // 2. Cast key to i8*
                Value *keyPtr = Builder.CreateIntToPtr(keyArg, Type::getInt8PtrTy(M.getContext()), "key_ptr");


                if(!is_update_func)
                {
                    // 3. Get or create the bpf_map_lookup_elem/bpf_map_delete_elem function with correct signature
                    FunctionType *lookupFnType = FunctionType::get(
                        Type::getInt8PtrTy(M.getContext()), // Return type: i8*
                        {Type::getInt8PtrTy(M.getContext()), Type::getInt8PtrTy(M.getContext())}, // Args: i8*, i8*
                        false
                    );
                    
                    // Function *lookupFn = cast<Function>(M.getOrInsertFunction("bpf_map_lookup_elem", lookupFnType).getCallee());
                    Function *lookupFn = Function::Create(lookupFnType, Function::ExternalLinkage, func_name, M);
                    // 4. Call bpf_map_lookup_elem
                    CallInst *newCall = Builder.CreateCall(lookupFn, {mapPtr, keyPtr}, "result_ptr");
                    
                    // 5. Cast result back to i64 if needed
                    Value *result = Builder.CreatePtrToInt(newCall, Type::getInt64Ty(M.getContext()));
                    
                    // Replace all uses of the old call with the new result
                    oldCall->replaceAllUsesWith(result);
                    
                    // Delete the old call
                    oldCall->eraseFromParent();
                }
                else
                {
                    Value* valuearg = oldCall->getArgOperand(2);
                    Value* flagarg = oldCall->getArgOperand(3);

                    Value *valptr = Builder.CreateIntToPtr(valuearg, Type::getInt8PtrTy(M.getContext()), "val_ptr");

                    FunctionType *updateFnType = FunctionType::get(
                        Type::getInt8PtrTy(M.getContext()), // Return type: i8*
                        {Type::getInt8PtrTy(M.getContext()), Type::getInt8PtrTy(M.getContext()), Type::getInt8PtrTy(M.getContext()), Type::getInt64Ty(M.getContext())}, // Args: i8*, i8*
                        false
                    );

                    Function *updateFn = Function::Create(updateFnType, Function::ExternalLinkage, func_name, M);
                    CallInst *newCall = Builder.CreateCall(updateFn, {mapPtr, keyPtr, valptr, flagarg}, "result_ptr");
                    Value *result = Builder.CreatePtrToInt(newCall, Type::getInt64Ty(M.getContext()));
                    oldCall->replaceAllUsesWith(result);
                    oldCall->eraseFromParent();
                }

                Function *FuncDecl = M.getFunction(func_name + ".toreplace");
                FuncDecl->eraseFromParent();

            }
        
        }
    }
};

PassPluginLibraryInfo getModulePassPluginInfo() {
    return {LLVM_PLUGIN_API_VERSION, "custom-bpf-pass", LLVM_VERSION_STRING,
        [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &MPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                    if (Name == "custom-bpf-pass") {
                        MPM.addPass(CustomModulePass());
                        return true;
                    }
                    return false;
                });
        }
    };
}

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
    return getModulePassPluginInfo();
}

} // namespace llvm