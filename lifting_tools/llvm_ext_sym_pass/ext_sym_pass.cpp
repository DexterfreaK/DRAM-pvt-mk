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

class InternalToExternal : public PassInfoMixin<InternalToExternal> {
  public:
    PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM) {
      bool Modified = false;
      
      // Iterate through all functions in the module
      for (Function &F : M) {
        if (F.getLinkage()) {
          F.setLinkage(llvm::GlobalValue::LinkageTypes::ExternalLinkage);
          Modified = true;
        }
      }
      
      return Modified ? PreservedAnalyses::none()
                      : PreservedAnalyses::all();
    }
};

PassPluginLibraryInfo getModulePassPluginInfo() {
    return {LLVM_PLUGIN_API_VERSION, "int-to-ext", LLVM_VERSION_STRING,
        [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &MPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                    if (Name == "int-to-ext") {
                        MPM.addPass(InternalToExternal());
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