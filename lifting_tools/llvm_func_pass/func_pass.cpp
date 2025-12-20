#include <bits/enable_special_members.h>
#include <llvm/IR/DerivedTypes.h>
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
#include <llvm/IR/Constants.h>
#include <llvm/Support/CommandLine.h>
#include <iostream>
#include <fstream>
#include <llvm/Support/raw_ostream.h>
#include <sstream>
#include <map>
#include <unordered_set>
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
        // 1) Create struct.bpf_map_def type : [Need to accomodate all types of maps here]
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
            std::cout << "Warning: No map configuration file provided\n";
            return PreservedAnalyses::none();
        }

        // 4) Remove existing global definitions for map names in our CSV
        std::vector<GlobalVariable*> globalsToRemove;
        for (auto &GV : M.globals()) {
            for (const auto &entry : mapIdToName) {
                if (GV.getName() == entry.second) {
                    std::cout << "Found map global to remove: " << GV.getName().str() << std::endl;
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

        std::cout << "transformMapLookups done" << std::endl;

        return PreservedAnalyses::none();
    }

private:
    void readMapConfig(const std::string &filename) {
        std::ifstream file(filename);
        
        if (!file.is_open()) {
            std::cout << "Error: Cannot open map config file: " << filename << "\n";
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
                    std::cout << "Loaded map config: ID " << id << " -> " << mapName << "\n";
                } catch (const std::exception &e) {
                    std::cout << "Error parsing map ID: " << idStr << "\n";
                }
            }
        }
    }

    void createMapDefinitions(Module &M, StructType *bpfMapDefType) {
        // [TODO: Support all types of maps]
        std::unordered_set<std::string> mapNames;
        for (const auto &entry : mapIdToName) {
            int mapId = entry.first;
            std::string mapName = entry.second;
            
            if (mapNames.find(mapName) != mapNames.end()) {
                continue;
            }
            mapNames.insert(mapName);

            std::cout << "map name : " << mapName << ", mapId : " << mapId << std::endl;

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
                            // std::cout << "getname : " << CalledF->getName() << std::endl;
                            if (CalledF->getName() == "bpf_map_lookup_elem.toreplace") {
                                CallsToReplace.push_back({CI,"bpf_map_lookup_elem"});
                            }
                            if (CalledF->getName() == "bpf_map_delete_elem.toreplace") {
                                CallsToReplace.push_back({CI,"bpf_map_delete_elem"});
                            }
                            if (CalledF->getName() == "bpf_map_update_elem.toreplace") {
                                CallsToReplace.push_back({CI,"bpf_map_update_elem"});
                            }
                            if (CalledF->getName() == "bpf_tail_call.toreplace") {
                                CallsToReplace.push_back({CI,"bpf_tail_call"});
                            }
                            // Ringbuf helper functions
                            if (CalledF->getName() == "bpf_ringbuf_reserve.toreplace") {
                                CallsToReplace.push_back({CI,"bpf_ringbuf_reserve"});
                            }
                            if (CalledF->getName() == "bpf_ringbuf_submit.toreplace") {
                                CallsToReplace.push_back({CI,"bpf_ringbuf_submit"});
                            }
                            if (CalledF->getName() == "bpf_ringbuf_discard.toreplace") {
                                CallsToReplace.push_back({CI,"bpf_ringbuf_discard"});
                            }
                            if (CalledF->getName() == "bpf_ringbuf_output.toreplace") {
                                CallsToReplace.push_back({CI,"bpf_ringbuf_output"});
                            }
                            // Simple helper functions that just need renaming (no map argument transformation)
                            if (CalledF->getName() == "bpf_ktime_get_ns.toreplace") {
                                CallsToReplace.push_back({CI,"bpf_ktime_get_ns"});
                            }
                            if (CalledF->getName() == "bpf_xdp_adjust_head.toreplace") {
                                CallsToReplace.push_back({CI,"bpf_xdp_adjust_head"});
                            }
                            if (CalledF->getName() == "bpf_get_smp_processor_id.toreplace") {
                                CallsToReplace.push_back({CI,"bpf_get_smp_processor_id"});
                            }
                            // Kprobe/tracepoint specific helpers
                            if (CalledF->getName() == "bpf_get_current_comm.toreplace") {
                                CallsToReplace.push_back({CI,"bpf_get_current_comm"});
                            }
                            if (CalledF->getName() == "bpf_probe_read.toreplace") {
                                CallsToReplace.push_back({CI,"bpf_probe_read"});
                            }
                            if (CalledF->getName() == "bpf_probe_read_str.toreplace") {
                                CallsToReplace.push_back({CI,"bpf_probe_read_str"});
                            }
                            if (CalledF->getName() == "bpf_trace_printk.toreplace") {
                                CallsToReplace.push_back({CI,"bpf_trace_printk"});
                            }
                            if (CalledF->getName() == "bpf_probe_write_user.toreplace") {
                                CallsToReplace.push_back({CI,"bpf_probe_write_user"});
                            }
                            if (CalledF->getName() == "bpf_override_return.toreplace") {
                                CallsToReplace.push_back({CI,"bpf_override_return"});
                            }
                        }
                    }
                }
            }
        }

        // Now replace each call
        for (auto &i : CallsToReplace) {
            replaceMapLookupDelete(i.first, M, i.second, i.second);
        }

        // Collect unique function names to erase
        std::unordered_set<std::string> functionsToErase;
        for (auto &i : CallsToReplace) {
            functionsToErase.insert(i.second + ".toreplace");
        }

        // Erase each unique function declaration once
        for (const auto &funcName : functionsToErase) {
            Function *FuncDecl = M.getFunction(funcName);
            std::cout << "call to replace :: " << funcName << std::endl;
            if (FuncDecl == nullptr) {
                std::cout << "Function not found: " << funcName << std::endl;
                continue;
            }
            // Check if function still has uses (shouldn't happen if all calls were replaced)
            if (!FuncDecl->use_empty()) {
                std::cout << "Warning: Function " << funcName << " still has uses, cannot erase" << std::endl;
                continue;
            }
            std::cout << "trying to erase : " << FuncDecl->getName().str() << std::endl;
            FuncDecl->eraseFromParent();
            std::cout << "ERASED" << std::endl;
        }
    }

    void replaceMapLookupDelete(CallInst *oldCall, Module &M, std::string func_name, std::string& func_type) {
        IRBuilder<> Builder(oldCall);

        // Handle simple helper functions that just need renaming (no map argument transformation)
        if (func_type.compare("bpf_ktime_get_ns") == 0) {
            // __u64 bpf_ktime_get_ns(void)
            std::cout << "simple helper: bpf_ktime_get_ns" << std::endl;
            FunctionType *funcType = FunctionType::get(
                Type::getInt64Ty(M.getContext()),
                {},
                false
            );
            Function *helperFunc = M.getFunction(func_name);
            if (!helperFunc) {
                helperFunc = Function::Create(funcType, Function::ExternalLinkage, func_name, M);
            }
            CallInst *newCall = Builder.CreateCall(helperFunc, {});
            oldCall->replaceAllUsesWith(newCall);
            oldCall->eraseFromParent();
            return;
        }

        if (func_type.compare("bpf_get_smp_processor_id") == 0) {
            // __u32 bpf_get_smp_processor_id(void)
            std::cout << "simple helper: bpf_get_smp_processor_id" << std::endl;
            FunctionType *funcType = FunctionType::get(
                Type::getInt32Ty(M.getContext()),
                {},
                false
            );
            Function *helperFunc = M.getFunction(func_name);
            if (!helperFunc) {
                helperFunc = Function::Create(funcType, Function::ExternalLinkage, func_name, M);
            }
            CallInst *newCall = Builder.CreateCall(helperFunc, {});
            // The old call might expect i64, so extend if needed
            Value *result = newCall;
            if (oldCall->getType()->isIntegerTy(64)) {
                result = Builder.CreateZExt(newCall, Type::getInt64Ty(M.getContext()), "smp_id_i64");
            }
            oldCall->replaceAllUsesWith(result);
            oldCall->eraseFromParent();
            return;
        }

        if (func_type.compare("bpf_xdp_adjust_head") == 0) {
            // int bpf_xdp_adjust_head(struct xdp_md *xdp_md, int delta)
            std::cout << "simple helper: bpf_xdp_adjust_head" << std::endl;
            Value *xdpArg = oldCall->getArgOperand(0);
            Value *deltaArg = oldCall->getArgOperand(1);

            FunctionType *funcType = FunctionType::get(
                Type::getInt32Ty(M.getContext()),
                {Type::getInt8PtrTy(M.getContext()), Type::getInt32Ty(M.getContext())},
                false
            );
            Function *helperFunc = M.getFunction(func_name);
            if (!helperFunc) {
                helperFunc = Function::Create(funcType, Function::ExternalLinkage, func_name, M);
            }

            Value *xdpPtr;
            if (xdpArg->getType()->isIntegerTy()) {
                xdpPtr = Builder.CreateIntToPtr(xdpArg, Type::getInt8PtrTy(M.getContext()), "xdp_ptr");
            } else if (xdpArg->getType()->isPointerTy()) {
                xdpPtr = Builder.CreateBitCast(xdpArg, Type::getInt8PtrTy(M.getContext()), "xdp_ptr");
            } else {
                xdpPtr = xdpArg;
            }

            Value *delta;
            if (deltaArg->getType()->isIntegerTy(64)) {
                delta = Builder.CreateTrunc(deltaArg, Type::getInt32Ty(M.getContext()), "delta_i32");
            } else if (deltaArg->getType()->isIntegerTy(32)) {
                delta = deltaArg;
            } else {
                delta = Builder.CreateIntCast(deltaArg, Type::getInt32Ty(M.getContext()), true, "delta_i32");
            }

            CallInst *newCall = Builder.CreateCall(helperFunc, {xdpPtr, delta});
            // Extend to i64 if the old call expects it
            Value *result = newCall;
            if (oldCall->getType()->isIntegerTy(64)) {
                result = Builder.CreateSExt(newCall, Type::getInt64Ty(M.getContext()), "result_i64");
            }
            oldCall->replaceAllUsesWith(result);
            oldCall->eraseFromParent();
            return;
        }

        // Handle ringbuf_submit and ringbuf_discard - these don't need map resolution
        // They take the reserved pointer as first argument, not the map
        if (func_type.compare("bpf_ringbuf_submit") == 0 || func_type.compare("bpf_ringbuf_discard") == 0) {
            std::cout << "ringbuf submit/discard" << std::endl;
            Value *dataArg = oldCall->getArgOperand(0);
            Value *flagsArg = oldCall->getArgOperand(1);

            // void bpf_ringbuf_submit(void *data, __u64 flags)
            FunctionType *funcType = FunctionType::get(
                Type::getVoidTy(M.getContext()),
                {Type::getInt8PtrTy(M.getContext()), Type::getInt64Ty(M.getContext())},
                false
            );

            Function *ringbufFunc = M.getFunction(func_name);
            if (!ringbufFunc) {
                ringbufFunc = Function::Create(funcType, Function::ExternalLinkage, func_name, M);
            }

            Value *dataPtr;
            if (dataArg->getType()->isIntegerTy()) {
                dataPtr = Builder.CreateIntToPtr(dataArg, Type::getInt8PtrTy(M.getContext()), "data_ptr");
            } else {
                dataPtr = Builder.CreateBitCast(dataArg, Type::getInt8PtrTy(M.getContext()), "data_ptr");
            }

            Value *flags;
            if (flagsArg->getType()->isIntegerTy(64)) {
                flags = flagsArg;
            } else {
                flags = Builder.CreateZExt(flagsArg, Type::getInt64Ty(M.getContext()), "flags_i64");
            }

            Builder.CreateCall(ringbufFunc, {dataPtr, flags});
            // These functions return void, so just erase the old call
            oldCall->eraseFromParent();
            return;
        }

        // Handle ringbuf_reserve - takes (map, size, flags), returns void*
        if (func_type.compare("bpf_ringbuf_reserve") == 0) {
            std::cout << "ringbuf reserve" << std::endl;
            Value *mapIdArg = oldCall->getArgOperand(0);
            Value *sizeArg = oldCall->getArgOperand(1);
            Value *flagsArg = oldCall->getArgOperand(2);

            if (ConstantInt *CI = dyn_cast<ConstantInt>(mapIdArg)) {
                int mapId = CI->getSExtValue();
                std::cout << "Found ringbuf_reserve with map ID: " << mapId << "\n";

                auto it = mapIdToName.find(mapId);
                if (it != mapIdToName.end()) {
                    std::cout << "  Mapped to map name: " << it->second << "\n";
                    std::string mapName = it->second;

                    GlobalVariable *mapGV = M.getGlobalVariable(mapName);
                    if (!mapGV) {
                        std::cout << "  Error: Map global variable not found: " << mapName << "\n";
                        return;
                    }

                    // void* bpf_ringbuf_reserve(void *ringbuf, __u64 size, __u64 flags)
                    FunctionType *funcType = FunctionType::get(
                        Type::getInt8PtrTy(M.getContext()),
                        {Type::getInt8PtrTy(M.getContext()), Type::getInt64Ty(M.getContext()), Type::getInt64Ty(M.getContext())},
                        false
                    );

                    Function *ringbufFunc = M.getFunction(func_name);
                    if (!ringbufFunc) {
                        ringbufFunc = Function::Create(funcType, Function::ExternalLinkage, func_name, M);
                    }

                    Value *mapPtr = Builder.CreateBitCast(mapGV, Type::getInt8PtrTy(M.getContext()), mapName + "_ptr");
                    
                    Value *size = sizeArg->getType()->isIntegerTy(64) ? sizeArg : 
                        Builder.CreateZExt(sizeArg, Type::getInt64Ty(M.getContext()), "size_i64");
                    Value *flags = flagsArg->getType()->isIntegerTy(64) ? flagsArg :
                        Builder.CreateZExt(flagsArg, Type::getInt64Ty(M.getContext()), "flags_i64");

                    CallInst *newCall = Builder.CreateCall(ringbufFunc, {mapPtr, size, flags}, "ringbuf_ptr");
                    Value *result = Builder.CreatePtrToInt(newCall, Type::getInt64Ty(M.getContext()));
                    oldCall->replaceAllUsesWith(result);
                    oldCall->eraseFromParent();
                } else {
                    std::cout << "  Warning: Map ID " << mapId << " not found for ringbuf_reserve\n";
                }
            }
            return;
        }

        // Handle ringbuf_output - takes (map, data, size, flags), returns long
        if (func_type.compare("bpf_ringbuf_output") == 0) {
            std::cout << "ringbuf output" << std::endl;
            Value *mapIdArg = oldCall->getArgOperand(0);
            Value *dataArg = oldCall->getArgOperand(1);
            Value *sizeArg = oldCall->getArgOperand(2);
            Value *flagsArg = oldCall->getArgOperand(3);

            if (ConstantInt *CI = dyn_cast<ConstantInt>(mapIdArg)) {
                int mapId = CI->getSExtValue();
                std::cout << "Found ringbuf_output with map ID: " << mapId << "\n";

                auto it = mapIdToName.find(mapId);
                if (it != mapIdToName.end()) {
                    std::cout << "  Mapped to map name: " << it->second << "\n";
                    std::string mapName = it->second;

                    GlobalVariable *mapGV = M.getGlobalVariable(mapName);
                    if (!mapGV) {
                        std::cout << "  Error: Map global variable not found: " << mapName << "\n";
                        return;
                    }

                    // long bpf_ringbuf_output(void *ringbuf, void *data, __u64 size, __u64 flags)
                    FunctionType *funcType = FunctionType::get(
                        Type::getInt64Ty(M.getContext()),
                        {Type::getInt8PtrTy(M.getContext()), Type::getInt8PtrTy(M.getContext()), 
                         Type::getInt64Ty(M.getContext()), Type::getInt64Ty(M.getContext())},
                        false
                    );

                    Function *ringbufFunc = M.getFunction(func_name);
                    if (!ringbufFunc) {
                        ringbufFunc = Function::Create(funcType, Function::ExternalLinkage, func_name, M);
                    }

                    Value *mapPtr = Builder.CreateBitCast(mapGV, Type::getInt8PtrTy(M.getContext()), mapName + "_ptr");
                    Value *dataPtr = dataArg->getType()->isIntegerTy() ? 
                        Builder.CreateIntToPtr(dataArg, Type::getInt8PtrTy(M.getContext()), "data_ptr") :
                        Builder.CreateBitCast(dataArg, Type::getInt8PtrTy(M.getContext()), "data_ptr");
                    Value *size = sizeArg->getType()->isIntegerTy(64) ? sizeArg : 
                        Builder.CreateZExt(sizeArg, Type::getInt64Ty(M.getContext()), "size_i64");
                    Value *flags = flagsArg->getType()->isIntegerTy(64) ? flagsArg :
                        Builder.CreateZExt(flagsArg, Type::getInt64Ty(M.getContext()), "flags_i64");

                    CallInst *newCall = Builder.CreateCall(ringbufFunc, {mapPtr, dataPtr, size, flags}, "ringbuf_result");
                    oldCall->replaceAllUsesWith(newCall);
                    oldCall->eraseFromParent();
                } else {
                    std::cout << "  Warning: Map ID " << mapId << " not found for ringbuf_output\n";
                }
            }
            return;
        }

        // Handle bpf_get_current_comm(void *buf, __u32 size) -> long
        if (func_type.compare("bpf_get_current_comm") == 0) {
            std::cout << "simple helper: bpf_get_current_comm" << std::endl;
            Value *bufArg = oldCall->getArgOperand(0);
            Value *sizeArg = oldCall->getArgOperand(1);

            FunctionType *funcType = FunctionType::get(
                Type::getInt64Ty(M.getContext()),
                {Type::getInt8PtrTy(M.getContext()), Type::getInt32Ty(M.getContext())},
                false
            );
            Function *helperFunc = M.getFunction(func_name);
            if (!helperFunc) {
                helperFunc = Function::Create(funcType, Function::ExternalLinkage, func_name, M);
            }

            Value *bufPtr;
            if (bufArg->getType()->isIntegerTy()) {
                bufPtr = Builder.CreateIntToPtr(bufArg, Type::getInt8PtrTy(M.getContext()), "buf_ptr");
            } else {
                bufPtr = Builder.CreateBitCast(bufArg, Type::getInt8PtrTy(M.getContext()), "buf_ptr");
            }

            Value *size;
            if (sizeArg->getType()->isIntegerTy(64)) {
                size = Builder.CreateTrunc(sizeArg, Type::getInt32Ty(M.getContext()), "size_i32");
            } else {
                size = sizeArg;
            }

            CallInst *newCall = Builder.CreateCall(helperFunc, {bufPtr, size});
            oldCall->replaceAllUsesWith(newCall);
            oldCall->eraseFromParent();
            return;
        }

        // Handle bpf_probe_read(void *dst, __u32 size, const void *unsafe_ptr) -> long
        if (func_type.compare("bpf_probe_read") == 0) {
            std::cout << "simple helper: bpf_probe_read" << std::endl;
            Value *dstArg = oldCall->getArgOperand(0);
            Value *sizeArg = oldCall->getArgOperand(1);
            Value *srcArg = oldCall->getArgOperand(2);

            FunctionType *funcType = FunctionType::get(
                Type::getInt64Ty(M.getContext()),
                {Type::getInt8PtrTy(M.getContext()), Type::getInt32Ty(M.getContext()), 
                 Type::getInt8PtrTy(M.getContext())},
                false
            );
            Function *helperFunc = M.getFunction(func_name);
            if (!helperFunc) {
                helperFunc = Function::Create(funcType, Function::ExternalLinkage, func_name, M);
            }

            Value *dstPtr;
            if (dstArg->getType()->isIntegerTy()) {
                dstPtr = Builder.CreateIntToPtr(dstArg, Type::getInt8PtrTy(M.getContext()), "dst_ptr");
            } else {
                dstPtr = Builder.CreateBitCast(dstArg, Type::getInt8PtrTy(M.getContext()), "dst_ptr");
            }

            Value *size;
            if (sizeArg->getType()->isIntegerTy(64)) {
                size = Builder.CreateTrunc(sizeArg, Type::getInt32Ty(M.getContext()), "size_i32");
            } else {
                size = sizeArg;
            }

            Value *srcPtr;
            if (srcArg->getType()->isIntegerTy()) {
                srcPtr = Builder.CreateIntToPtr(srcArg, Type::getInt8PtrTy(M.getContext()), "src_ptr");
            } else {
                srcPtr = Builder.CreateBitCast(srcArg, Type::getInt8PtrTy(M.getContext()), "src_ptr");
            }

            CallInst *newCall = Builder.CreateCall(helperFunc, {dstPtr, size, srcPtr});
            oldCall->replaceAllUsesWith(newCall);
            oldCall->eraseFromParent();
            return;
        }

        // Handle bpf_probe_read_str(void *dst, __u32 size, const void *unsafe_ptr) -> long
        if (func_type.compare("bpf_probe_read_str") == 0) {
            std::cout << "simple helper: bpf_probe_read_str" << std::endl;
            Value *dstArg = oldCall->getArgOperand(0);
            Value *sizeArg = oldCall->getArgOperand(1);
            Value *srcArg = oldCall->getArgOperand(2);

            FunctionType *funcType = FunctionType::get(
                Type::getInt64Ty(M.getContext()),
                {Type::getInt8PtrTy(M.getContext()), Type::getInt32Ty(M.getContext()), 
                 Type::getInt8PtrTy(M.getContext())},
                false
            );
            Function *helperFunc = M.getFunction(func_name);
            if (!helperFunc) {
                helperFunc = Function::Create(funcType, Function::ExternalLinkage, func_name, M);
            }

            Value *dstPtr;
            if (dstArg->getType()->isIntegerTy()) {
                dstPtr = Builder.CreateIntToPtr(dstArg, Type::getInt8PtrTy(M.getContext()), "dst_ptr");
            } else {
                dstPtr = Builder.CreateBitCast(dstArg, Type::getInt8PtrTy(M.getContext()), "dst_ptr");
            }

            Value *size;
            if (sizeArg->getType()->isIntegerTy(64)) {
                size = Builder.CreateTrunc(sizeArg, Type::getInt32Ty(M.getContext()), "size_i32");
            } else {
                size = sizeArg;
            }

            Value *srcPtr;
            if (srcArg->getType()->isIntegerTy()) {
                srcPtr = Builder.CreateIntToPtr(srcArg, Type::getInt8PtrTy(M.getContext()), "src_ptr");
            } else {
                srcPtr = Builder.CreateBitCast(srcArg, Type::getInt8PtrTy(M.getContext()), "src_ptr");
            }

            CallInst *newCall = Builder.CreateCall(helperFunc, {dstPtr, size, srcPtr});
            oldCall->replaceAllUsesWith(newCall);
            oldCall->eraseFromParent();
            return;
        }

        // Handle bpf_trace_printk(const char *fmt, __u32 fmt_size, ...) -> long
        if (func_type.compare("bpf_trace_printk") == 0) {
            std::cout << "simple helper: bpf_trace_printk" << std::endl;
            // This is a variadic function - we'll just replace it with a no-op that returns 0
            // Get the correct function signature
            FunctionType *funcType = FunctionType::get(
                Type::getInt64Ty(M.getContext()),
                {Type::getInt8PtrTy(M.getContext()), Type::getInt32Ty(M.getContext())},
                true  // variadic
            );
            Function *helperFunc = M.getFunction(func_name);
            if (!helperFunc) {
                helperFunc = Function::Create(funcType, Function::ExternalLinkage, func_name, M);
            }

            // Collect all arguments and convert types as needed
            std::vector<Value*> args;
            for (unsigned i = 0; i < oldCall->arg_size(); i++) {
                Value *arg = oldCall->getArgOperand(i);
                if (i == 0 || i == 2) {  // String pointer arguments
                    if (arg->getType()->isIntegerTy()) {
                        arg = Builder.CreateIntToPtr(arg, Type::getInt8PtrTy(M.getContext()), "arg_ptr");
                    } else if (arg->getType()->isPointerTy()) {
                        arg = Builder.CreateBitCast(arg, Type::getInt8PtrTy(M.getContext()), "arg_ptr");
                    }
                } else if (i == 1) {  // Size argument
                    if (arg->getType()->isIntegerTy(64)) {
                        arg = Builder.CreateTrunc(arg, Type::getInt32Ty(M.getContext()), "size_i32");
                    }
                }
                args.push_back(arg);
            }

            CallInst *newCall = Builder.CreateCall(helperFunc, args);
            oldCall->replaceAllUsesWith(newCall);
            oldCall->eraseFromParent();
            return;
        }

        // Handle bpf_probe_write_user(void *dst, const void *src, __u32 len) -> long
        if (func_type.compare("bpf_probe_write_user") == 0) {
            std::cout << "simple helper: bpf_probe_write_user" << std::endl;
            Value *dstArg = oldCall->getArgOperand(0);
            Value *srcArg = oldCall->getArgOperand(1);
            Value *lenArg = oldCall->getArgOperand(2);

            FunctionType *funcType = FunctionType::get(
                Type::getInt64Ty(M.getContext()),
                {Type::getInt8PtrTy(M.getContext()), Type::getInt8PtrTy(M.getContext()),
                 Type::getInt32Ty(M.getContext())},
                false
            );
            Function *helperFunc = M.getFunction(func_name);
            if (!helperFunc) {
                helperFunc = Function::Create(funcType, Function::ExternalLinkage, func_name, M);
            }

            Value *dstPtr;
            if (dstArg->getType()->isIntegerTy()) {
                dstPtr = Builder.CreateIntToPtr(dstArg, Type::getInt8PtrTy(M.getContext()), "dst_ptr");
            } else {
                dstPtr = Builder.CreateBitCast(dstArg, Type::getInt8PtrTy(M.getContext()), "dst_ptr");
            }

            Value *srcPtr;
            if (srcArg->getType()->isIntegerTy()) {
                srcPtr = Builder.CreateIntToPtr(srcArg, Type::getInt8PtrTy(M.getContext()), "src_ptr");
            } else {
                srcPtr = Builder.CreateBitCast(srcArg, Type::getInt8PtrTy(M.getContext()), "src_ptr");
            }

            Value *len;
            if (lenArg->getType()->isIntegerTy(64)) {
                len = Builder.CreateTrunc(lenArg, Type::getInt32Ty(M.getContext()), "len_i32");
            } else {
                len = lenArg;
            }

            CallInst *newCall = Builder.CreateCall(helperFunc, {dstPtr, srcPtr, len});
            oldCall->replaceAllUsesWith(newCall);
            oldCall->eraseFromParent();
            return;
        }

        // Handle bpf_override_return(struct pt_regs *regs, __u64 rc) -> long
        if (func_type.compare("bpf_override_return") == 0) {
            std::cout << "simple helper: bpf_override_return" << std::endl;
            Value *regsArg = oldCall->getArgOperand(0);
            Value *rcArg = oldCall->getArgOperand(1);

            FunctionType *funcType = FunctionType::get(
                Type::getInt64Ty(M.getContext()),
                {Type::getInt8PtrTy(M.getContext()), Type::getInt64Ty(M.getContext())},
                false
            );
            Function *helperFunc = M.getFunction(func_name);
            if (!helperFunc) {
                helperFunc = Function::Create(funcType, Function::ExternalLinkage, func_name, M);
            }

            Value *regsPtr;
            if (regsArg->getType()->isIntegerTy()) {
                regsPtr = Builder.CreateIntToPtr(regsArg, Type::getInt8PtrTy(M.getContext()), "regs_ptr");
            } else {
                regsPtr = Builder.CreateBitCast(regsArg, Type::getInt8PtrTy(M.getContext()), "regs_ptr");
            }

            Value *rc;
            if (rcArg->getType()->isIntegerTy(64)) {
                rc = rcArg;
            } else {
                rc = Builder.CreateZExt(rcArg, Type::getInt64Ty(M.getContext()), "rc_i64");
            }

            CallInst *newCall = Builder.CreateCall(helperFunc, {regsPtr, rc});
            oldCall->replaceAllUsesWith(newCall);
            oldCall->eraseFromParent();
            return;
        }

        if (func_type.compare("bpf_tail_call") == 0) {
            std::cout << "tail call" << std::endl;
            Value *ctxArg = oldCall->getArgOperand(0);
            Value *progArrayMapArg = oldCall->getArgOperand(1);
            Value *indexArg = oldCall->getArgOperand(2);

            if (ConstantInt *CI = dyn_cast<ConstantInt>(progArrayMapArg)) {
                int mapId = CI->getSExtValue();
                std::cout << "Found map lookup with ID: " << mapId << "\n";
                auto it = mapIdToName.find(mapId);
                if (it != mapIdToName.end()) {
                    std::cout << "  Mapped to map name: " << it->second << "\n";
                    std::string mapName = it->second;
                    GlobalVariable *mapGV = M.getGlobalVariable(mapName);
                    if (!mapGV) {
                        std::cout << "  Error: Map global variable not found: " << mapName << "\n";
                        return;
                    }

                    // bpf_tail_call returns i64 (long)
                    FunctionType *tailCallFuncType = FunctionType::get(
                        Type::getInt64Ty(M.getContext()),
                        {Type::getInt8PtrTy(M.getContext()), Type::getInt8PtrTy(M.getContext()), Type::getInt32Ty(M.getContext())},
                        false
                    );

                    Function *tailCallFunc = M.getFunction(func_name); // Check if already exists
                    if (!tailCallFunc) {
                        tailCallFunc = Function::Create(
                            tailCallFuncType,
                            Function::ExternalLinkage,
                            func_name,
                            M
                        );
                    }

                    // Convert ctxArg to pointer if it's an integer
                    Value* ctxptr;
                    if (ctxArg->getType()->isIntegerTy()) {
                        ctxptr = Builder.CreateIntToPtr(ctxArg, Type::getInt8PtrTy(M.getContext()), "ctx_ptr");
                    } else {
                        ctxptr = Builder.CreateBitCast(ctxArg, Type::getInt8PtrTy(M.getContext()), "ctx_ptr");
                    }

                    // Use the actual map global variable, not the map ID
                    Value* progArrayMapPtr = Builder.CreateBitCast(mapGV, Type::getInt8PtrTy(M.getContext()), "prog_array_map_ptr");

                    // Convert indexArg from i64 to i32 if necessary
                    Value* indexValue;
                    if (indexArg->getType()->isIntegerTy(64)) {
                        indexValue = Builder.CreateTrunc(indexArg, Type::getInt32Ty(M.getContext()), "index_i32");
                    } else {
                        indexValue = indexArg;
                    }

                    CallInst *newCall = Builder.CreateCall(tailCallFunc, {ctxptr, progArrayMapPtr, indexValue}, "tail_call_result");
                    oldCall->replaceAllUsesWith(newCall);
                    oldCall->eraseFromParent();
                } else {
                    // Unknown program array map ID - still replace with direct pointer
                    std::cout << "  Warning: Tail call map ID " << mapId << " not found in relocation table\n";
                    
                    // bpf_tail_call returns i64 (long)
                    FunctionType *tailCallFuncType = FunctionType::get(
                        Type::getInt64Ty(M.getContext()),
                        {Type::getInt8PtrTy(M.getContext()), Type::getInt8PtrTy(M.getContext()), Type::getInt32Ty(M.getContext())},
                        false
                    );

                    Function *tailCallFunc = M.getFunction(func_name);
                    if (!tailCallFunc) {
                        tailCallFunc = Function::Create(tailCallFuncType, Function::ExternalLinkage, func_name, M);
                    }

                    Value* ctxptr;
                    if (ctxArg->getType()->isIntegerTy()) {
                        ctxptr = Builder.CreateIntToPtr(ctxArg, Type::getInt8PtrTy(M.getContext()), "ctx_ptr");
                    } else {
                        ctxptr = Builder.CreateBitCast(ctxArg, Type::getInt8PtrTy(M.getContext()), "ctx_ptr");
                    }

                    Value* progArrayMapPtr = Builder.CreateIntToPtr(progArrayMapArg, Type::getInt8PtrTy(M.getContext()), "unknown_prog_array_ptr");

                    Value* indexValue;
                    if (indexArg->getType()->isIntegerTy(64)) {
                        indexValue = Builder.CreateTrunc(indexArg, Type::getInt32Ty(M.getContext()), "index_i32");
                    } else {
                        indexValue = indexArg;
                    }

                    CallInst *newCall = Builder.CreateCall(tailCallFunc, {ctxptr, progArrayMapPtr, indexValue}, "tail_call_result");
                    oldCall->replaceAllUsesWith(newCall);
                    oldCall->eraseFromParent();
                }
            }
            
        } else {
            std::cout << "not a tail call" << std::endl;
            // Get the map ID from the first argument
            Value *mapIdArg = oldCall->getArgOperand(0);
            Value *keyArg = oldCall->getArgOperand(1);
            
            // If it's a constant, we can determine which map it's accessing
            if (ConstantInt *CI = dyn_cast<ConstantInt>(mapIdArg)) {
                int mapId = CI->getSExtValue();
                std::cout << "Found map lookup with ID: " << mapId << "\n";
                
                // Find if we have a name for this ID
                auto it = mapIdToName.find(mapId);
                if (it != mapIdToName.end()) {
                    std::cout << "  Mapped to map name: " << it->second << "\n";

                    std::string mapName = it->second;

                    // Get the map global variable
                    GlobalVariable *mapGV = M.getGlobalVariable(mapName);
                    if (!mapGV) {
                        std::cout << "  Error: Map global variable not found: " << mapName << "\n";
                        return;
                    }

                    // 1. Cast map global variable to i8*
                    Value *mapPtr = Builder.CreateBitCast(mapGV, Type::getInt8PtrTy(M.getContext()), mapName + "_ptr");

                    // 2. Cast key to i8*
                    Value *keyPtr = Builder.CreateIntToPtr(keyArg, Type::getInt8PtrTy(M.getContext()), "key_ptr");


                    if(func_type.compare("bpf_map_lookup_elem") == 0 || func_type.compare("bpf_map_delete_elem") == 0)
                    {
                        std::cout << "lookup or delete" << std::endl;
                        // 3. Get or create the function with correct signature
                        FunctionType *lookupFnType = FunctionType::get(
                            Type::getInt8PtrTy(M.getContext()), // Return type: i8*
                            {Type::getInt8PtrTy(M.getContext()), Type::getInt8PtrTy(M.getContext())}, // Args: i8*, i8*
                            false
                        );

                        Function *lookupFn = M.getFunction(func_name); // Check if already exists
                        if (!lookupFn) {
                            lookupFn = Function::Create(
                                lookupFnType,
                                Function::ExternalLinkage,
                                func_name,
                                M
                            );
                        }

                        // 4. Call bpf_map_lookup_elem
                        CallInst *newCall = Builder.CreateCall(lookupFn, {mapPtr, keyPtr}, "result_ptr");

                        // 5. Cast result back to i64 if needed
                        Value *result = Builder.CreatePtrToInt(newCall, Type::getInt64Ty(M.getContext()));

                        // Replace all uses of the old call with the new result
                        oldCall->replaceAllUsesWith(result);

                        // Delete the old call
                        oldCall->eraseFromParent();
                    }
                    else if (func_type.compare("bpf_map_update_elem") == 0)
                    {
                        std::cout << "update" << std::endl;
                        Value* valuearg = oldCall->getArgOperand(2);
                        Value* flagarg = oldCall->getArgOperand(3);

                        Value *valptr = Builder.CreateIntToPtr(valuearg, Type::getInt8PtrTy(M.getContext()), "val_ptr");

                        FunctionType *updateFnType = FunctionType::get(
                            Type::getInt8PtrTy(M.getContext()), // Return type: i8*
                            {Type::getInt8PtrTy(M.getContext()), Type::getInt8PtrTy(M.getContext()), Type::getInt8PtrTy(M.getContext()), Type::getInt64Ty(M.getContext())}, // Args: i8*, i8*
                            false
                        );

                        Function *updateFn = M.getFunction(func_name);
                        if (!updateFn) {
                            updateFn = Function::Create(updateFnType, Function::ExternalLinkage, func_name, M);
                        }
                        CallInst *newCall = Builder.CreateCall(updateFn, {mapPtr, keyPtr, valptr, flagarg}, "result_ptr");
                        Value *result = Builder.CreatePtrToInt(newCall, Type::getInt64Ty(M.getContext()));
                        oldCall->replaceAllUsesWith(result);
                        oldCall->eraseFromParent();
                    }
                } else {
                    // Map ID not found in relocation table - might be a stack address or invalid
                    // Still replace to remove .toreplace suffix, but use the ID directly as pointer
                    std::cout << "  Warning: Map ID " << mapId << " not found in relocation table, using as direct pointer\n";
                    
                    Value *mapPtr = Builder.CreateIntToPtr(mapIdArg, Type::getInt8PtrTy(M.getContext()), "unknown_map_ptr");
                    Value *keyPtr = Builder.CreateIntToPtr(keyArg, Type::getInt8PtrTy(M.getContext()), "key_ptr");
                    
                    if(func_type.compare("bpf_map_lookup_elem") == 0 || func_type.compare("bpf_map_delete_elem") == 0) {
                        FunctionType *lookupFnType = FunctionType::get(
                            Type::getInt8PtrTy(M.getContext()),
                            {Type::getInt8PtrTy(M.getContext()), Type::getInt8PtrTy(M.getContext())},
                            false
                        );
                        
                        Function *lookupFn = M.getFunction(func_name);
                        if (!lookupFn) {
                            lookupFn = Function::Create(lookupFnType, Function::ExternalLinkage, func_name, M);
                        }
                        
                        CallInst *newCall = Builder.CreateCall(lookupFn, {mapPtr, keyPtr}, "result_ptr");
                        Value *result = Builder.CreatePtrToInt(newCall, Type::getInt64Ty(M.getContext()));
                        oldCall->replaceAllUsesWith(result);
                        oldCall->eraseFromParent();
                    } else if (func_type.compare("bpf_map_update_elem") == 0) {
                        Value* valuearg = oldCall->getArgOperand(2);
                        Value* flagarg = oldCall->getArgOperand(3);
                        Value *valptr = Builder.CreateIntToPtr(valuearg, Type::getInt8PtrTy(M.getContext()), "val_ptr");
                        
                        FunctionType *updateFnType = FunctionType::get(
                            Type::getInt8PtrTy(M.getContext()),
                            {Type::getInt8PtrTy(M.getContext()), Type::getInt8PtrTy(M.getContext()), Type::getInt8PtrTy(M.getContext()), Type::getInt64Ty(M.getContext())},
                            false
                        );
                        
                        Function *updateFn = M.getFunction(func_name);
                        if (!updateFn) {
                            updateFn = Function::Create(updateFnType, Function::ExternalLinkage, func_name, M);
                        }
                        
                        CallInst *newCall = Builder.CreateCall(updateFn, {mapPtr, keyPtr, valptr, flagarg}, "result_ptr");
                        Value *result = Builder.CreatePtrToInt(newCall, Type::getInt64Ty(M.getContext()));
                        oldCall->replaceAllUsesWith(result);
                        oldCall->eraseFromParent();
                    }
                }
            
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

} // namespace llvm

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
    return llvm::getModulePassPluginInfo();
}