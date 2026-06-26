// clam_bridge: rewrites Clam-emitted assume calls (verifier.assume / llvm.assume
// tagged with the !clam metadata) into klee_assume(i64) calls that KLEE's
// SpecialFunctionHandler intercepts. Clam writes invariants as i1 booleans;
// KLEE's klee_assume takes uintptr_t, so we zext.
//
// Invocation: opt-13 -load-pass-plugin <path>/libclam_bridge.so \
//             -passes=clam-bridge in.bc -o out.bc
//
// Optional flag: --clam-bridge-only-tagged (default true) — only rewrites
// calls carrying the !clam metadata Clam adds via --crab-promote-assume,
// so we don't accidentally pick up llvm.assume calls inserted by other
// passes (e.g. clang's own optimisation hints).

#include <llvm/IR/Function.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/PassManager.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Intrinsics.h>
#include <llvm/IR/Metadata.h>
#include <llvm/Pass.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Passes/PassPlugin.h>

#include <iostream>
#include <vector>

namespace llvm {

static cl::opt<bool> OnlyTagged(
    "clam-bridge-only-tagged",
    cl::desc("Only rewrite assume calls carrying the !clam metadata tag"),
    cl::init(true));

namespace {

static bool hasClamTag(const CallInst *CI) {
  return CI->getMetadata("clam") != nullptr;
}

// Returns true if F is one of the assume-shaped functions Clam emits.
static bool isAssumeLike(const Function *F) {
  if (!F) return false;
  StringRef N = F->getName();
  if (N == "verifier.assume") return true;
  if (F->getIntrinsicID() == Intrinsic::assume) return true;
  return false;
}

struct ClamBridgePass : public PassInfoMixin<ClamBridgePass> {
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
    LLVMContext &ctx = M.getContext();

    // klee_assume signature: void klee_assume(uintptr_t).
    // uintptr_t is i64 on x86-64 (which matches our target datalayout).
    Type *I64 = Type::getInt64Ty(ctx);
    FunctionType *kleeAssumeTy =
        FunctionType::get(Type::getVoidTy(ctx), {I64}, false);
    FunctionCallee kleeAssume =
        M.getOrInsertFunction("klee_assume", kleeAssumeTy);

    size_t rewritten = 0, skippedUntagged = 0, skippedTrivial = 0;
    std::vector<CallInst *> toErase;

    for (Function &F : M) {
      for (BasicBlock &BB : F) {
        for (Instruction &I : BB) {
          auto *CI = dyn_cast<CallInst>(&I);
          if (!CI) continue;
          if (!isAssumeLike(CI->getCalledFunction())) continue;
          if (OnlyTagged && !hasClamTag(CI)) {
            ++skippedUntagged;
            continue;
          }
          if (CI->arg_size() != 1) continue;
          Value *cond = CI->getArgOperand(0);
          if (!cond->getType()->isIntegerTy(1)) continue;

          // Trivial assumes are no-ops; drop them entirely so KLEE doesn't
          // spend solver effort on tautologies.
          if (auto *C = dyn_cast<ConstantInt>(cond)) {
            if (C->isOne()) {
              toErase.push_back(CI);
              ++skippedTrivial;
              continue;
            }
          }

          IRBuilder<> B(CI);
          Value *condI64 = B.CreateZExt(cond, I64, "clam_b_");
          CallInst *newCall = B.CreateCall(kleeAssume, {condI64});
          newCall->setDebugLoc(CI->getDebugLoc());
          toErase.push_back(CI);
          ++rewritten;
        }
      }
    }

    for (CallInst *CI : toErase) CI->eraseFromParent();

    // The original verifier.assume declaration may now be unused; drop it.
    if (Function *VA = M.getFunction("verifier.assume")) {
      if (VA->use_empty()) VA->eraseFromParent();
    }

    std::cerr << "[clam-bridge] rewrote " << rewritten
              << " assume calls -> klee_assume; dropped " << skippedTrivial
              << " trivial; skipped " << skippedUntagged
              << " untagged\n";

    return rewritten ? PreservedAnalyses::none() : PreservedAnalyses::all();
  }
};

} // anonymous namespace

PassPluginLibraryInfo getClamBridgePassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "clam-bridge", LLVM_VERSION_STRING,
    [](PassBuilder &PB) {
      PB.registerPipelineParsingCallback(
          [](StringRef Name, ModulePassManager &MPM,
             ArrayRef<PassBuilder::PipelineElement>) {
            if (Name == "clam-bridge") {
              MPM.addPass(ClamBridgePass());
              return true;
            }
            return false;
          });
    }
  };
}

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return getClamBridgePassPluginInfo();
}

} // namespace llvm
