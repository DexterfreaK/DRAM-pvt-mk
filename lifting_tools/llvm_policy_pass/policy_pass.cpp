// policy_pass: optional LLVM module pass that prunes policy-irrelevant code
// before KLEE. Reads the same JSON spec KLEE consumes
// (`helper_func`, `map_access`, `packet_constraints`) and stubs out functions
// that cannot possibly affect a policy-relevant operation. Runs as
// `-passes=policy-prune` via opt; the trailing `globaldce,dce,simplifycfg`
// chain cleans up the stubs.

#include <llvm/IR/Function.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/PassManager.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/GlobalVariable.h>
#include <llvm/IR/Operator.h>
#include <llvm/Pass.h>
#include <llvm/Support/Casting.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Passes/PassPlugin.h>
#include <llvm/Analysis/CallGraph.h>

#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <set>
#include <unordered_set>
#include <utility>
#include <cctype>
#include <cstdint>

namespace llvm {

static cl::opt<std::string> PolicySpecFile(
    "policy-spec",
    cl::desc("Path to policy spec JSON (helper_func / map_access / packet_constraints)"),
    cl::value_desc("filename"));

namespace {

// ----------------------- minimal JSON reader -----------------------
// The policy spec file is small, well-formed, and produced by the same
// tooling that KLEE consumes. A hand-rolled reader avoids pulling in a
// dependency. Supports: objects, arrays, strings, numbers, bool, null.

struct JsonValue {
  enum class Type { Null, Bool, Number, String, Array, Object } type = Type::Null;
  bool b = false;
  double n = 0;
  std::string s;
  std::vector<JsonValue> arr;
  std::vector<std::pair<std::string, JsonValue>> obj;

  const JsonValue *find(const std::string &key) const {
    if (type != Type::Object) return nullptr;
    for (auto &kv : obj) if (kv.first == key) return &kv.second;
    return nullptr;
  }
};

struct JsonParser {
  const std::string &src;
  size_t i = 0;
  bool ok = true;
  std::string err;

  explicit JsonParser(const std::string &s) : src(s) {}

  void skipWs() {
    while (i < src.size() && std::isspace(static_cast<unsigned char>(src[i]))) ++i;
  }

  bool match(char c) {
    skipWs();
    if (i < src.size() && src[i] == c) { ++i; return true; }
    return false;
  }

  void expect(char c) {
    if (!match(c)) { ok = false; err = std::string("expected ") + c; }
  }

  std::string parseString() {
    std::string out;
    if (!match('"')) { ok = false; err = "expected string"; return out; }
    while (i < src.size() && src[i] != '"') {
      char c = src[i++];
      if (c == '\\' && i < src.size()) {
        char e = src[i++];
        switch (e) {
          case 'n': out += '\n'; break;
          case 't': out += '\t'; break;
          case 'r': out += '\r'; break;
          case '"': out += '"'; break;
          case '\\': out += '\\'; break;
          case '/': out += '/'; break;
          default: out += e; break;
        }
      } else {
        out += c;
      }
    }
    expect('"');
    return out;
  }

  double parseNumber() {
    skipWs();
    size_t start = i;
    if (i < src.size() && (src[i] == '-' || src[i] == '+')) ++i;
    while (i < src.size() && (std::isdigit(static_cast<unsigned char>(src[i])) ||
                              src[i] == '.' || src[i] == 'e' || src[i] == 'E' ||
                              src[i] == '+' || src[i] == '-'))
      ++i;
    return std::stod(src.substr(start, i - start));
  }

  JsonValue parseValue() {
    skipWs();
    JsonValue v;
    if (i >= src.size()) { ok = false; err = "unexpected eof"; return v; }
    char c = src[i];
    if (c == '"') {
      v.type = JsonValue::Type::String;
      v.s = parseString();
    } else if (c == '{') {
      ++i; v.type = JsonValue::Type::Object;
      skipWs();
      if (!match('}')) {
        while (ok) {
          skipWs();
          std::string k = parseString();
          skipWs(); expect(':');
          JsonValue val = parseValue();
          v.obj.emplace_back(std::move(k), std::move(val));
          skipWs();
          if (match(',')) continue;
          expect('}'); break;
        }
      }
    } else if (c == '[') {
      ++i; v.type = JsonValue::Type::Array;
      skipWs();
      if (!match(']')) {
        while (ok) {
          v.arr.push_back(parseValue());
          skipWs();
          if (match(',')) continue;
          expect(']'); break;
        }
      }
    } else if (c == 't' || c == 'f') {
      v.type = JsonValue::Type::Bool;
      if (src.compare(i, 4, "true") == 0) { v.b = true; i += 4; }
      else if (src.compare(i, 5, "false") == 0) { v.b = false; i += 5; }
      else { ok = false; err = "bad bool"; }
    } else if (c == 'n') {
      if (src.compare(i, 4, "null") == 0) { v.type = JsonValue::Type::Null; i += 4; }
      else { ok = false; err = "bad null"; }
    } else {
      v.type = JsonValue::Type::Number;
      v.n = parseNumber();
    }
    return v;
  }
};

// ----------------------- policy spec -----------------------

struct PacketRange { int64_t lo; int64_t hi; };

struct PolicySpec {
  std::set<std::string> helpers;
  std::set<std::string> maps;
  std::vector<PacketRange> readRanges;
  std::vector<PacketRange> writeRanges;
  std::string entryName;
};

// Parses "0-146", "54", or "x" (wildcard/star).
// Wildcard means the entire packet; we represent that with a single
// [INT64_MIN, INT64_MAX] range so overlap tests trivially succeed.
static bool parseRange(const std::string &s, PacketRange &out) {
  if (s.empty()) return false;
  if (s == "x" || s == "X" || s == "*") {
    out.lo = INT64_MIN; out.hi = INT64_MAX; return true;
  }
  size_t dash = s.find('-');
  try {
    if (dash == std::string::npos) {
      int64_t v = std::stoll(s);
      out.lo = v; out.hi = v;
    } else {
      out.lo = std::stoll(s.substr(0, dash));
      out.hi = std::stoll(s.substr(dash + 1));
    }
  } catch (...) { return false; }
  return true;
}

static void collectRanges(const JsonValue *arr, std::vector<PacketRange> &out) {
  if (!arr || arr->type != JsonValue::Type::Array) return;
  for (auto &v : arr->arr) {
    if (v.type != JsonValue::Type::String) continue;
    PacketRange r;
    if (parseRange(v.s, r)) out.push_back(r);
  }
}

static bool loadPolicy(const std::string &path, PolicySpec &spec) {
  std::ifstream f(path);
  if (!f.is_open()) {
    std::cerr << "[policy-prune] cannot open spec: " << path << "\n";
    return false;
  }
  std::stringstream ss; ss << f.rdbuf();
  std::string text = ss.str();
  JsonParser p(text);
  JsonValue root = p.parseValue();
  if (!p.ok || root.type != JsonValue::Type::Object) {
    std::cerr << "[policy-prune] malformed spec: " << p.err << "\n";
    return false;
  }

  if (auto *h = root.find("helper_func")) {
    if (h->type == JsonValue::Type::Array)
      for (auto &v : h->arr)
        if (v.type == JsonValue::Type::String) spec.helpers.insert(v.s);
  }
  if (auto *m = root.find("map_access")) {
    if (m->type == JsonValue::Type::Array)
      for (auto &v : m->arr) {
        if (v.type != JsonValue::Type::Object) continue;
        if (auto *n = v.find("name"))
          if (n->type == JsonValue::Type::String) spec.maps.insert(n->s);
      }
  }
  if (auto *pc = root.find("packet_constraints")) {
    if (pc->type == JsonValue::Type::Array)
      for (auto &v : pc->arr) {
        if (v.type != JsonValue::Type::Object) continue;
        collectRanges(v.find("read-access"), spec.readRanges);
        collectRanges(v.find("write-access"), spec.writeRanges);
      }
  }
  if (auto *e = root.find("entry_function")) {
    if (e->type == JsonValue::Type::String) spec.entryName = e->s;
  }
  return true;
}

// ----------------------- relevance analysis -----------------------

static bool rangesOverlap(const std::vector<PacketRange> &rs, int64_t lo, int64_t hi) {
  for (auto &r : rs) {
    if (r.lo <= hi && lo <= r.hi) return true;
  }
  return false;
}

// Trace through bitcasts/GEPs to find a ConstantInt offset, if any.
// Returns true if the offset could be determined exactly; otherwise false,
// which the caller treats as "conservatively relevant".
static bool tryConstantOffset(Value *ptr, const DataLayout &DL, int64_t &off) {
  off = 0;
  while (ptr) {
    if (auto *gep = dyn_cast<GetElementPtrInst>(ptr)) {
      APInt acc(DL.getIndexTypeSizeInBits(gep->getType()), 0);
      if (!gep->accumulateConstantOffset(DL, acc)) return false;
      off += acc.getSExtValue();
      ptr = gep->getPointerOperand();
    } else if (auto *ce = dyn_cast<ConstantExpr>(ptr)) {
      if (ce->getOpcode() == Instruction::GetElementPtr) {
        auto *gep = cast<GEPOperator>(ce);
        APInt acc(DL.getIndexTypeSizeInBits(gep->getType()), 0);
        if (!gep->accumulateConstantOffset(DL, acc)) return false;
        off += acc.getSExtValue();
        ptr = gep->getPointerOperand();
      } else if (ce->getOpcode() == Instruction::BitCast ||
                 ce->getOpcode() == Instruction::AddrSpaceCast) {
        ptr = ce->getOperand(0);
      } else return false;
    } else if (auto *bc = dyn_cast<BitCastInst>(ptr)) {
      ptr = bc->getOperand(0);
    } else {
      break;
    }
  }
  return true;
}

// Best-effort check: is `ptr` derived from a packet buffer, i.e. from
// xdp_md->data (or __sk_buff->data)? We walk back through casts/GEPs/loads
// and look for either a function arg whose pointee is %struct.xdp_md /
// %struct.__sk_buff, or a LoadInst reading one of those struct's data
// fields.
static bool isPacketPointer(Value *ptr, std::unordered_set<Value *> &seen) {
  if (!ptr || !seen.insert(ptr).second) return false;
  if (auto *bc = dyn_cast<BitCastInst>(ptr))
    return isPacketPointer(bc->getOperand(0), seen);
  if (auto *gep = dyn_cast<GetElementPtrInst>(ptr))
    return isPacketPointer(gep->getPointerOperand(), seen);
  if (auto *ce = dyn_cast<ConstantExpr>(ptr)) {
    if (ce->getOpcode() == Instruction::BitCast ||
        ce->getOpcode() == Instruction::GetElementPtr)
      return isPacketPointer(ce->getOperand(0), seen);
  }
  if (auto *ii = dyn_cast<IntToPtrInst>(ptr))
    return isPacketPointer(ii->getOperand(0), seen);
  if (auto *pi = dyn_cast<PtrToIntInst>(ptr))
    return isPacketPointer(pi->getOperand(0), seen);
  if (auto *ld = dyn_cast<LoadInst>(ptr)) {
    Value *src = ld->getPointerOperand();
    // Walk through the pointer operand looking at the source type name.
    Type *srcTy = src->getType();
    if (auto *pt = dyn_cast<PointerType>(srcTy)) {
      Type *el = pt->getPointerElementType();
      if (auto *st = dyn_cast<StructType>(el)) {
        if (st->hasName()) {
          StringRef n = st->getName();
          if (n.contains("xdp_md") || n.contains("__sk_buff") ||
              n.contains("xdp_buff"))
            return true;
        }
      }
    }
    return isPacketPointer(src, seen);
  }
  if (auto *arg = dyn_cast<Argument>(ptr)) {
    if (auto *pt = dyn_cast<PointerType>(arg->getType())) {
      Type *el = pt->getPointerElementType();
      if (auto *st = dyn_cast<StructType>(el)) {
        if (st->hasName()) {
          StringRef n = st->getName();
          if (n.contains("xdp_md") || n.contains("__sk_buff") ||
              n.contains("xdp_buff"))
            return true;
        }
      }
    }
  }
  return false;
}

static bool isPacketPointer(Value *ptr) {
  std::unordered_set<Value *> seen;
  return isPacketPointer(ptr, seen);
}

// ----------------------- the pass -----------------------

class PolicyPrunePass : public PassInfoMixin<PolicyPrunePass> {
public:
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM) {
    PolicySpec spec;
    if (PolicySpecFile.empty()) {
      std::cerr << "[policy-prune] no -policy-spec provided, skipping\n";
      return PreservedAnalyses::all();
    }
    if (!loadPolicy(PolicySpecFile, spec)) {
      std::cerr << "[policy-prune] failed to load spec; skipping\n";
      return PreservedAnalyses::all();
    }

    // Step 1: find the entry function. If unspecified, take the first
    // non-intrinsic function with a body whose name doesn't look like a
    // helper (i.e. not starting with bpf_ or klee_).
    Function *entry = nullptr;
    if (!spec.entryName.empty())
      entry = M.getFunction(spec.entryName);
    if (!entry) {
      for (Function &F : M) {
        if (F.isDeclaration() || F.isIntrinsic()) continue;
        StringRef n = F.getName();
        if (n.startswith("bpf_") || n.startswith("klee_") ||
            n.startswith("llvm.")) continue;
        entry = &F;
        break;
      }
    }

    // Step 2: collect policy-relevant instructions. Mark their enclosing
    // functions as directly-relevant.
    std::set<Function *> directly;
    if (entry) directly.insert(entry);

    const DataLayout &DL = M.getDataLayout();
    for (Function &F : M) {
      if (F.isDeclaration()) continue;
      for (BasicBlock &BB : F) {
        for (Instruction &I : BB) {
          if (auto *ci = dyn_cast<CallInst>(&I)) {
            Function *callee = ci->getCalledFunction();
            if (callee && !callee->getName().empty()) {
              std::string cn = callee->getName().str();
              if (spec.helpers.count(cn)) {
                directly.insert(&F);
                continue;
              }
            }
          }
          // Map-global loads/stores/GEPs: inspect pointer operand chain
          // for a GlobalVariable whose name is in the relevant-maps set.
          auto checkMapOperand = [&](Value *ptr) {
            Value *cur = ptr;
            while (cur) {
              if (auto *gv = dyn_cast<GlobalVariable>(cur)) {
                if (spec.maps.count(gv->getName().str())) {
                  directly.insert(&F);
                }
                return;
              }
              if (auto *gep = dyn_cast<GetElementPtrInst>(cur)) {
                cur = gep->getPointerOperand(); continue;
              }
              if (auto *bc = dyn_cast<BitCastInst>(cur)) {
                cur = bc->getOperand(0); continue;
              }
              if (auto *ce = dyn_cast<ConstantExpr>(cur)) {
                if (ce->getOpcode() == Instruction::GetElementPtr ||
                    ce->getOpcode() == Instruction::BitCast) {
                  cur = ce->getOperand(0); continue;
                }
              }
              break;
            }
          };

          if (auto *ld = dyn_cast<LoadInst>(&I)) {
            checkMapOperand(ld->getPointerOperand());
          } else if (auto *st = dyn_cast<StoreInst>(&I)) {
            checkMapOperand(st->getPointerOperand());
          }

          // Packet loads/stores: any access to a pointer derived from
          // xdp_md->data marks the function relevant, regardless of
          // whether the offset overlaps a listed range. KLEE treats
          // out-of-range packet ops as violations; if we stub the
          // containing function, KLEE never observes the violating
          // op and the verdict silently flips to VALID. Range overlap
          // is a hint for what *should* be there, not a license to
          // erase what *is* there.
          auto checkPacket = [&](Value *ptr, bool /*isWrite*/) {
            if (isPacketPointer(ptr)) directly.insert(&F);
          };
          if (auto *ld = dyn_cast<LoadInst>(&I)) {
            checkPacket(ld->getPointerOperand(), false);
          } else if (auto *st = dyn_cast<StoreInst>(&I)) {
            checkPacket(st->getPointerOperand(), true);
          }
        }
      }
    }

    // Step 3: transitive closure via call graph. A function is relevant if
    // it (transitively) calls any directly-relevant function.
    CallGraph CG(M);
    std::set<Function *> relevant = directly;

    // Iterate to fixpoint: add F if any of F's callees is already relevant.
    bool changed = true;
    while (changed) {
      changed = false;
      for (auto &entry : CG) {
        const Function *fn = entry.first;
        if (!fn) continue;
        Function *F = const_cast<Function *>(fn);
        if (F->isDeclaration() || relevant.count(F)) continue;
        CallGraphNode *N = entry.second.get();
        for (auto &callee : *N) {
          Function *cf = callee.second->getFunction();
          if (cf && relevant.count(cf)) {
            relevant.insert(F);
            changed = true;
            break;
          }
        }
      }
    }

    // Address-taken conservatism: if a relevant function ends up with its
    // address stored/passed somewhere, some other function that observed
    // that address might indirectly depend on it. We conservatively mark
    // every function whose address is taken (and has a body) as relevant,
    // which covers tail-call tables and function-pointer dispatch tables.
    for (Function &F : M) {
      if (F.isDeclaration()) continue;
      if (relevant.count(&F)) continue;
      if (F.hasAddressTaken()) relevant.insert(&F);
    }

    // Soundness guard: any function whose NAME matches a helper listed in
    // the spec must keep its body. KLEE's policy tracking fires inside
    // these helper implementations (e.g. bpf_map_update_elem records the
    // write). If we stub them, the tracking never runs and a write to a
    // read-only map looks valid (FALSE POSITIVE on the verdict).
    for (Function &F : M) {
      if (F.isDeclaration()) continue;
      if (spec.helpers.count(F.getName().str()))
        relevant.insert(&F);
    }

    // Downward transitive closure: keep the callees of every relevant
    // function. Without this, helper impls (and anything they depend on)
    // get stubbed to `ret undef`, which breaks KLEE's execution of the
    // very code we want to track.
    changed = true;
    while (changed) {
      changed = false;
      for (auto &entry : CG) {
        const Function *fn = entry.first;
        if (!fn) continue;
        Function *F = const_cast<Function *>(fn);
        if (!relevant.count(F)) continue;
        CallGraphNode *N = entry.second.get();
        for (auto &callee : *N) {
          Function *cf = callee.second->getFunction();
          if (!cf || cf->isDeclaration()) continue;
          if (!relevant.count(cf)) {
            relevant.insert(cf);
            changed = true;
          }
        }
      }
    }

    // Step 4a: stub irrelevant function bodies.
    size_t kept = 0, stubbed = 0;
    for (Function &F : M) {
      if (F.isDeclaration() || F.isIntrinsic()) continue;
      StringRef name = F.getName();
      if (name.startswith("klee_") || name.startswith("llvm.")) {
        ++kept; continue;
      }
      if (relevant.count(&F)) { ++kept; continue; }

      // Drop all basic blocks.
      std::vector<BasicBlock *> toErase;
      for (BasicBlock &BB : F) toErase.push_back(&BB);
      for (BasicBlock *BB : toErase) BB->dropAllReferences();
      for (BasicBlock *BB : toErase) BB->eraseFromParent();

      // Emit a single `ret <undef>` entry block.
      LLVMContext &C = F.getContext();
      BasicBlock *entryBB = BasicBlock::Create(C, "entry", &F);
      IRBuilder<> B(entryBB);
      Type *rt = F.getReturnType();
      if (rt->isVoidTy()) B.CreateRetVoid();
      else B.CreateRet(UndefValue::get(rt));
      ++stubbed;
    }

    // Step 4b: strip @llvm.used / @llvm.compiler.used so the subsequent
    // globaldce pass can drop map globals that truly have no remaining
    // uses. We deliberately do NOT erase map globals here: if the code
    // still references an "unlisted" map (e.g. via BPF_MAP_INIT from
    // main()), forcing an undef there hides the very violation KLEE is
    // meant to flag. globaldce will only remove globals with zero uses.
    if (auto *u = M.getGlobalVariable("llvm.used")) u->eraseFromParent();
    if (auto *u = M.getGlobalVariable("llvm.compiler.used")) u->eraseFromParent();
    size_t erasedGlobals = 0;

    std::cerr << "[policy-prune] kept " << kept
              << " functions, stubbed " << stubbed
              << ", erased " << erasedGlobals << " map globals\n";

    return PreservedAnalyses::none();
  }
};

} // end anonymous namespace

PassPluginLibraryInfo getPolicyPrunePassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "policy-prune", LLVM_VERSION_STRING,
    [](PassBuilder &PB) {
      PB.registerPipelineParsingCallback(
          [](StringRef Name, ModulePassManager &MPM,
             ArrayRef<PassBuilder::PipelineElement>) {
            if (Name == "policy-prune") {
              MPM.addPass(PolicyPrunePass());
              return true;
            }
            return false;
          });
    }
  };
}

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return getPolicyPrunePassPluginInfo();
}

} // namespace llvm
