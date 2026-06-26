// selective_packet_sym: optional LLVM module pass that keeps the existing
// whole-packet klee_make_symbolic() call, then immediately pins selected packet
// fields to fixed values when an irrelevance sidecar spec says they can be
// concrete and the main policy does not mark them relevant.

#include <llvm/IR/Constants.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/GlobalVariable.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/PassManager.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Passes/PassPlugin.h>
#include <llvm/Support/Casting.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/raw_ostream.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <fstream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace llvm {

static cl::opt<std::string> SelectivePolicySpecFile(
    "packet-policy-spec",
    cl::desc("Path to main policy spec JSON"),
    cl::value_desc("filename"));

static cl::opt<std::string> PacketIrrelevanceSpecFile(
    "packet-irrelevance-spec",
    cl::desc("Path to packet irrelevance JSON"),
    cl::value_desc("filename"));

namespace {

struct JsonValue {
  enum class Type { Null, Bool, Number, String, Array, Object } type = Type::Null;
  bool b = false;
  double n = 0;
  std::string s;
  std::vector<JsonValue> arr;
  std::vector<std::pair<std::string, JsonValue>> obj;

  const JsonValue *find(const std::string &key) const {
    if (type != Type::Object) return nullptr;
    for (const auto &kv : obj)
      if (kv.first == key) return &kv.second;
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
    while (i < src.size() && std::isspace(static_cast<unsigned char>(src[i])))
      ++i;
  }

  bool match(char c) {
    skipWs();
    if (i < src.size() && src[i] == c) {
      ++i;
      return true;
    }
    return false;
  }

  void expect(char c) {
    if (!match(c)) {
      ok = false;
      err = std::string("expected ") + c;
    }
  }

  std::string parseString() {
    std::string out;
    if (!match('"')) {
      ok = false;
      err = "expected string";
      return out;
    }
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
    if (i >= src.size()) {
      ok = false;
      err = "unexpected eof";
      return v;
    }
    char c = src[i];
    if (c == '"') {
      v.type = JsonValue::Type::String;
      v.s = parseString();
    } else if (c == '{') {
      ++i;
      v.type = JsonValue::Type::Object;
      skipWs();
      if (!match('}')) {
        while (ok) {
          std::string k = parseString();
          skipWs();
          expect(':');
          JsonValue val = parseValue();
          v.obj.emplace_back(std::move(k), std::move(val));
          skipWs();
          if (match(',')) continue;
          expect('}');
          break;
        }
      }
    } else if (c == '[') {
      ++i;
      v.type = JsonValue::Type::Array;
      skipWs();
      if (!match(']')) {
        while (ok) {
          v.arr.push_back(parseValue());
          skipWs();
          if (match(',')) continue;
          expect(']');
          break;
        }
      }
    } else if (c == 't' || c == 'f') {
      v.type = JsonValue::Type::Bool;
      if (src.compare(i, 4, "true") == 0) {
        v.b = true;
        i += 4;
      } else if (src.compare(i, 5, "false") == 0) {
        v.b = false;
        i += 5;
      } else {
        ok = false;
        err = "bad bool";
      }
    } else if (c == 'n') {
      if (src.compare(i, 4, "null") == 0) {
        v.type = JsonValue::Type::Null;
        i += 4;
      } else {
        ok = false;
        err = "bad null";
      }
    } else {
      v.type = JsonValue::Type::Number;
      v.n = parseNumber();
    }
    return v;
  }
};

struct ByteRange {
  uint64_t lo;
  uint64_t hi;
};

using FieldMap = std::unordered_map<std::string, ByteRange>;
struct PacketRegionSpec {
  std::string name;
  std::vector<unsigned> gepIndices;
  uint64_t size;
  bool isPolicyField;
};

enum class PacketLayoutKind {
  Unsupported,
  StandardIpv4Tcp,
  KatranIpv4Tcp,
};

static FieldMap knownFieldRanges() {
  return {
      {"ethertype",      {12, 13}},
      {"ihl_version",    {14, 14}},
      {"tos",            {15, 15}},
      {"tot_len",        {16, 17}},
      {"ip_id",          {18, 19}},
      {"frag_off",       {20, 21}},
      {"ttl",            {22, 22}},
      {"protocol",       {23, 23}},
      {"ip_check",       {24, 25}},
      {"sIP",            {26, 29}},
      {"dIP",            {30, 33}},
      {"sPort",          {34, 35}},
      {"dPort",          {36, 37}},
      {"tcp_seq",        {38, 41}},
      {"tcp_ack_seq",    {42, 45}},
      {"tcp_flags",      {46, 47}},
      {"tcp_window",     {48, 49}},
      {"tcp_check",      {50, 51}},
      {"tcp_urg_ptr",    {52, 53}},
  };
}

static std::string readFile(const std::string &path) {
  std::ifstream f(path);
  if (!f.is_open()) return "";
  std::stringstream ss;
  ss << f.rdbuf();
  return ss.str();
}

static bool loadJsonRoot(const std::string &path, JsonValue &root, const char *tag) {
  std::string text = readFile(path);
  if (text.empty()) {
    errs() << "[" << tag << "] cannot open spec: " << path << "\n";
    return false;
  }
  JsonParser p(text);
  root = p.parseValue();
  if (!p.ok || root.type != JsonValue::Type::Object) {
    errs() << "[" << tag << "] malformed spec: " << p.err << "\n";
    return false;
  }
  return true;
}

static void markFieldRelevantForOffset(uint64_t off, uint64_t size,
                                       const FieldMap &fieldRanges,
                                       std::unordered_set<std::string> &relevant) {
  uint64_t hi = off + (size ? size - 1 : 0);
  for (const auto &kv : fieldRanges) {
    if (kv.second.lo <= hi && off <= kv.second.hi) relevant.insert(kv.first);
  }
}

static void collectDirectRelevantFields(const JsonValue &root,
                                        const FieldMap &fieldRanges,
                                        std::unordered_set<std::string> &relevant) {
  if (const JsonValue *pcs = root.find("packet_constraints")) {
    if (pcs->type == JsonValue::Type::Array) {
      static const char *fieldNames[] = {"sIP", "dIP", "sPort", "dPort"};
      for (const JsonValue &entry : pcs->arr) {
        if (entry.type != JsonValue::Type::Object) continue;
        for (const char *name : fieldNames) {
          if (const JsonValue *fv = entry.find(name)) {
            if (fv->type == JsonValue::Type::String && fv->s != "*") relevant.insert(name);
          }
        }
      }
    }
  }

  if (const JsonValue *conds = root.find("conditional_policies")) {
    if (conds->type != JsonValue::Type::Object) return;
    for (const auto &policyKv : conds->obj) {
      const JsonValue &policy = policyKv.second;
      if (policy.type != JsonValue::Type::Object) continue;
      const JsonValue *mc = policy.find("memory_conditions");
      if (!mc || mc->type != JsonValue::Type::Array) continue;
      for (const JsonValue &cond : mc->arr) {
        if (cond.type != JsonValue::Type::Object) continue;
        const JsonValue *off = cond.find("offset");
        const JsonValue *size = cond.find("size");
        if (!off || !size || off->type != JsonValue::Type::Number ||
            size->type != JsonValue::Type::Number)
          continue;
        markFieldRelevantForOffset(static_cast<uint64_t>(off->n),
                                   static_cast<uint64_t>(size->n),
                                   fieldRanges, relevant);
      }
    }
  }
}

static void collectIrrelevantFields(const JsonValue &root,
                                    std::unordered_set<std::string> &irrelevant) {
  const JsonValue *items = root.find("irrelevant_packet_items");
  if (!items || items->type != JsonValue::Type::Array) return;
  for (const JsonValue &entry : items->arr) {
    if (entry.type == JsonValue::Type::String) irrelevant.insert(entry.s);
  }
}

static std::vector<PacketRegionSpec> standardPacketRegions() {
  return {
      {"ethertype",   {0, 2},        2, true},
      {"ihl_version", {1, 0},        1, true},
      {"tos",         {1, 1},        1, true},
      {"tot_len",     {1, 2},        2, true},
      {"ip_id",       {1, 3},        2, true},
      {"frag_off",    {1, 4},        2, true},
      {"ttl",         {1, 5},        1, true},
      {"protocol",    {1, 6},        1, true},
      {"ip_check",    {1, 7},        2, true},
      {"sIP",         {1, 8, 0, 0},  4, true},
      {"dIP",         {1, 8, 0, 1},  4, true},
      {"sPort",       {2, 0},        2, true},
      {"dPort",       {2, 1},        2, true},
  };
}

static std::vector<PacketRegionSpec> katranIpv4PacketRegions() {
  return {
      {"ethertype",   {1, 2},        2, true},
      {"ihl_version", {2, 0},        1, true},
      {"tos",         {2, 1},        1, true},
      {"tot_len",     {2, 2},        2, true},
      {"ip_id",       {2, 3},        2, true},
      {"frag_off",    {2, 4},        2, true},
      {"ttl",         {2, 5},        1, true},
      {"protocol",    {2, 6},        1, true},
      {"ip_check",    {2, 7},        2, true},
      {"sIP",         {2, 8, 0, 0},  4, true},
      {"dIP",         {2, 8, 0, 1},  4, true},
      {"sPort",       {3, 0},        2, true},
      {"dPort",       {3, 1},        2, true},
      {"tcp_seq",     {3, 2},        4, true},
      {"tcp_ack_seq", {3, 3},        4, true},
      {"tcp_flags",   {3, 4},        2, true},
      {"tcp_window",  {3, 5},        2, true},
      {"tcp_check",   {3, 6},        2, true},
      {"tcp_urg_ptr", {3, 7},        2, true},
  };
}

static PacketLayoutKind detectPacketLayout(const std::string &baseName) {
  if (baseName == "constraint_access_user_pkt" ||
      baseName == "constraint_access_user_buf" ||
      baseName == "constraint_access_packet") {
    return PacketLayoutKind::StandardIpv4Tcp;
  }
  if (baseName == "constraint_access_lb_pkt") {
    return PacketLayoutKind::KatranIpv4Tcp;
  }
  return PacketLayoutKind::Unsupported;
}

static bool isHarnessPacketSymbolic(CallInst &call, uint64_t &sizeOut,
                                    std::string &baseNameOut,
                                    PacketLayoutKind &layoutOut) {
  Function *callee = call.getCalledFunction();
  if (!callee || callee->getName() != "klee_make_symbolic") return false;

  ConstantInt *sizeC = dyn_cast<ConstantInt>(call.getArgOperand(1));
  if (!sizeC) return false;

  std::string baseName;
  if (GlobalVariable *gv = dyn_cast<GlobalVariable>(call.getArgOperand(2)->stripPointerCasts())) {
    if (ConstantDataArray *arr = dyn_cast<ConstantDataArray>(gv->getInitializer())) {
      if (arr->isCString()) baseName = arr->getAsCString().str();
    }
  }
  layoutOut = detectPacketLayout(baseName);
  if (layoutOut == PacketLayoutKind::Unsupported) return false;

  sizeOut = sizeC->getZExtValue();
  baseNameOut = baseName;
  return true;
}

class SelectivePacketSymPass : public PassInfoMixin<SelectivePacketSymPass> {
 public:
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
    if (SelectivePolicySpecFile.empty() || PacketIrrelevanceSpecFile.empty()) {
      errs() << "[selective-packet-sym] missing spec, skipping\n";
      return PreservedAnalyses::all();
    }

    JsonValue policyRoot;
    JsonValue irrelevanceRoot;
    if (!loadJsonRoot(SelectivePolicySpecFile, policyRoot, "selective-packet-sym") ||
        !loadJsonRoot(PacketIrrelevanceSpecFile, irrelevanceRoot, "selective-packet-sym")) {
      return PreservedAnalyses::all();
    }

    const FieldMap fieldRanges = knownFieldRanges();
    std::unordered_set<std::string> relevantFields;
    std::unordered_set<std::string> irrelevantFields;
    collectDirectRelevantFields(policyRoot, fieldRanges, relevantFields);
    collectIrrelevantFields(irrelevanceRoot, irrelevantFields);

    std::unordered_set<std::string> concretizedFields;
    for (const std::string &field : irrelevantFields) {
      auto it = fieldRanges.find(field);
      if (it == fieldRanges.end()) continue;
      if (relevantFields.count(field)) {
        errs() << "[selective-packet-sym] keeping policy-relevant field symbolic: "
               << field << "\n";
        continue;
      }
      concretizedFields.insert(field);
    }

    if (concretizedFields.empty()) {
      errs() << "[selective-packet-sym] no eligible irrelevant fields, skipping\n";
      return PreservedAnalyses::all();
    }

    LLVMContext &ctx = M.getContext();
    bool changed = false;
    unsigned concretizedCalls = 0;

    for (Function &F : M) {
      for (BasicBlock &BB : F) {
        for (auto it = BB.begin(), end = BB.end(); it != end;) {
          Instruction *inst = &*it++;
          auto *call = dyn_cast<CallInst>(inst);
          if (!call) continue;

          uint64_t packetSize = 0;
          std::string baseName;
          PacketLayoutKind layout = PacketLayoutKind::Unsupported;
          if (!isHarnessPacketSymbolic(*call, packetSize, baseName, layout)) continue;
          (void)packetSize;
          (void)baseName;

          std::vector<PacketRegionSpec> regions;
          if (layout == PacketLayoutKind::StandardIpv4Tcp) {
            regions = standardPacketRegions();
          } else if (layout == PacketLayoutKind::KatranIpv4Tcp) {
            regions = katranIpv4PacketRegions();
          } else {
            continue;
          }

          IRBuilder<> irb(call->getNextNode());
          Value *typedPacketPtr = call->getArgOperand(0)->stripPointerCasts();
          if (!typedPacketPtr->getType()->isPointerTy()) continue;

          for (const PacketRegionSpec &region : regions) {
            if (!region.isPolicyField || !concretizedFields.count(region.name)) continue;

            Value *regionPtr = typedPacketPtr;
            Type *currentType =
                cast<PointerType>(typedPacketPtr->getType())->getPointerElementType();
            bool badRegion = false;

            for (unsigned idx : region.gepIndices) {
              if (auto *structTy = dyn_cast<StructType>(currentType)) {
                if (idx >= structTy->getNumElements()) {
                  badRegion = true;
                  break;
                }
                regionPtr = irb.CreateStructGEP(structTy, regionPtr, idx);
                currentType = structTy->getElementType(idx);
              } else if (auto *arrayTy = dyn_cast<ArrayType>(currentType)) {
                Value *zero = ConstantInt::get(Type::getInt32Ty(ctx), 0);
                Value *iv = ConstantInt::get(Type::getInt32Ty(ctx), idx);
                regionPtr = irb.CreateInBoundsGEP(arrayTy, regionPtr, {zero, iv});
                currentType = arrayTy->getElementType();
              } else {
                badRegion = true;
                break;
              }
            }
            if (badRegion) continue;

            irb.CreateStore(Constant::getNullValue(currentType), regionPtr);
          }

          changed = true;
          ++concretizedCalls;
        }
      }
    }

    if (changed) {
      errs() << "[selective-packet-sym] concretized fields after " << concretizedCalls
             << " whole-packet symbolic calls\n";
      return PreservedAnalyses::none();
    }
    return PreservedAnalyses::all();
  }
};

}  // namespace

PassPluginLibraryInfo getSelectivePacketSymPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "selective-packet-sym", LLVM_VERSION_STRING,
          [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &MPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                  if (Name == "selective-packet-sym") {
                    MPM.addPass(SelectivePacketSymPass());
                    return true;
                  }
                  return false;
                });
          }};
}

extern "C" LLVM_ATTRIBUTE_WEAK PassPluginLibraryInfo llvmGetPassPluginInfo() {
  return getSelectivePacketSymPassPluginInfo();
}

}  // namespace llvm
