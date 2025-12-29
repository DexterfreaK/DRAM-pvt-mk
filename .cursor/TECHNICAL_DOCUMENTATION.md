# DRACO-pvt: Technical Architecture Documentation

## Table of Contents
1. [Overview](#overview)
2. [System Architecture](#system-architecture)
3. [eBPF Lifting Process](#ebpf-lifting-process)
4. [LLVM Passes](#llvm-passes)
5. [Template Generation System](#template-generation-system)
6. [KLEE Integration](#klee-integration)
7. [eBPF-SE: Stubbed Helper Functions](#ebpf-se-stubbed-helper-functions)
8. [Verification Workflow](#verification-workflow)
9. [Memory Model and Constraints](#memory-model-and-constraints)
10. [Known Limitations and Challenges](#known-limitations-and-challenges)

---

## Overview

DRACO-pvt (Dynamic Runtime Analysis and Constraint Optimization - Program Verification Tool) is a comprehensive framework for verifying eBPF (extended Berkeley Packet Filter) programs using symbolic execution. The toolchain lifts eBPF bytecode to LLVM IR, applies custom transformations, generates verification harnesses, and uses KLEE for symbolic execution to detect security violations.

### Key Components

1. **BPF Lifter**: Converts eBPF bytecode to LLVM IR
2. **LLVM Passes**: Transform lifted IR for verification
3. **Template Generator**: Creates KLEE verification harnesses
4. **eBPF-SE**: Stubbed implementations of eBPF helper functions
5. **KLEE Integration**: Symbolic execution engine with custom extensions

---

## System Architecture

```
┌─────────────────┐
│  eBPF Object    │
│   File (.o)     │
└────────┬────────┘
         │
         ▼
┌─────────────────────────────────┐
│   Step 1: BPF Lifter            │
│   - Parse ELF sections          │
│   - Extract eBPF instructions    │
│   - Convert to LLVM IR          │
└────────┬────────────────────────┘
         │
         ▼
┌─────────────────────────────────┐
│   Step 2: LLVM Optimization     │
│   - opt -O3                     │
└────────┬────────────────────────┘
         │
         ▼
┌─────────────────────────────────┐
│   Step 3: Custom LLVM Passes     │
│   - Function Pass (map removal)  │
│   - External Symbol Pass         │
└────────┬────────────────────────┘
         │
         ▼
┌─────────────────────────────────┐
│   Step 4: Template Generation   │
│   - Jinja2 template rendering   │
│   - Context setup               │
│   - Map initialization          │
└────────┬────────────────────────┘
         │
         ▼
┌─────────────────────────────────┐
│   Step 5: IR Linking            │
│   - Link template + lifted IR   │
└────────┬────────────────────────┘
         │
         ▼
┌─────────────────────────────────┐
│   Step 6: KLEE Execution        │
│   - Symbolic execution          │
│   - Constraint solving          │
│   - Violation detection         │
└─────────────────────────────────┘
```

---

## eBPF Lifting Process

### Architecture

The BPF lifter (`bpf_lifter/`) is implemented in C++ using LLVM 15 and libbpf. It processes eBPF object files and generates LLVM IR.

### Key Components

#### 1. ELF Parsing (`Decompiler::process_elf`)

- **Input**: eBPF object file (`.o`)
- **Process**:
  - Uses `libbpf` to open and parse the object file
  - Iterates over all eBPF programs in the object
  - Extracts program metadata (name, section, instructions)
  - Identifies and processes BPF maps

#### 2. Program Lifting (`Decompiler::lift_program`)

For each eBPF program:

**Instruction Extraction**:
```cpp
auto instr = bpf_program__insns(prog);
auto cnt = bpf_program__insn_cnt(prog);
// Stores all bpf_insn structures in a vector
```

**Basic Block Analysis**:
- Identifies basic block boundaries
- Handles jumps, branches, and function calls
- Creates LLVM BasicBlocks for each eBPF basic block

**Register Model**:
- eBPF has 11 registers (R0-R10)
- R10 is the frame pointer (stack pointer)
- R0 is the return value register
- R1-R5 are argument/scratch registers
- R6-R9 are callee-saved registers

**Stack Model**:
- eBPF stack size: 512 bytes (EBPF_STACK_SIZE)
- Implemented as `i64` array: `STACK_SIZE = (512 + 7) / 8 = 64` elements
- Stack grows downward (R10 points to end)

**Instruction Lifting**:

The lifter processes each eBPF instruction type:

- **ALU Operations**: `BPF_ADD`, `BPF_SUB`, `BPF_MUL`, etc.
  - Converted to LLVM arithmetic instructions
  - Handles both 32-bit and 64-bit operations

- **Load/Store Operations**: `BPF_LDX`, `BPF_STX`, `BPF_ST`
  - Memory accesses converted to LLVM load/store
  - Stack accesses use GEP (GetElementPtr) on stack array
  - Map accesses handled via helper function calls

- **Branch Operations**: `BPF_JMP`, `BPF_JMP32`
  - Conditional branches → LLVM `br` instructions
  - Unconditional jumps → LLVM `br` to target block
  - Function calls → LLVM `call` instructions

- **Helper Function Calls**: `BPF_CALL`
  - Helper ID extracted from instruction immediate
  - Replaced with placeholder calls: `bpf_helper_name.toreplace`
  - Actual implementation linked later via stubs

**Map Handling**:
- Maps identified from ELF sections (`.maps`, BTF data)
- Map metadata stored for later processing
- Map lookups converted to `bpf_map_lookup_elem.toreplace` calls

**Function Linking**:
- Multiple programs in one object file → multiple LLVM modules
- Modules linked together into single module
- Function names preserved with section prefixes

### Output

The lifter generates LLVM IR with:
- Function definitions for each eBPF program
- Placeholder calls for helper functions (`.toreplace` suffix)
- Map global variables (later removed by passes)
- Stack and register simulation code

---

## LLVM Passes

### 1. Function Pass (`llvm_func_pass/`)

**Purpose**: Transform map accesses and remove map globals

**Key Operations**:

#### Map Global Removal
- Reads map ID → name mapping from CSV file
- Removes global variable definitions for maps
- Creates new `struct bpf_map_def` external declarations

#### Map Lookup Transformation
```cpp
// Before: bpf_map_lookup_elem.toreplace(map_id, key)
// After:  bpf_map_lookup_elem(&map_name, key)
```

The pass:
1. Identifies `bpf_map_lookup_elem.toreplace` calls
2. Extracts map ID from first argument
3. Looks up map name from CSV mapping
4. Replaces call with `bpf_map_lookup_elem(&map_name, key)`
5. Updates function signature to use `struct bpf_map_def*`

#### Helper Function Replacement
- Removes `.toreplace` suffix from helper function calls
- Ensures helper functions are declared (not defined) in IR
- Actual implementations provided by eBPF-SE stubs

**Implementation Details**:
- Uses LLVM PassManager (new pass manager API)
- Module-level pass (processes entire module)
- Preserves function signatures and types

### 2. External Symbol Pass (`llvm_ext_sym_pass/`)

**Purpose**: Convert integer constants to external symbols

**Operations**:
- Identifies integer constants that should be external symbols
- Replaces with external symbol references
- Used for map IDs and other compile-time constants

---

## Template Generation System

### Overview

The template system (`draco_template.j2`) generates C code that:
1. Sets up symbolic inputs for KLEE
2. Initializes BPF maps with test data
3. Calls the lifted eBPF program
4. Provides verification harness

### Template Structure

#### 1. Header Includes and Defines

```c
#define DRACO_LIFTER_MODE 1  // Enables lifter-specific behavior
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
// ... other includes
```

#### 2. Helper Function Declarations

Based on detected helper usage, defines are set:
```c
#ifndef USES_BPF_PROBE_READ
#define USES_BPF_PROBE_READ
#endif
```

#### 3. Map Definitions

For each map in the program:
```c
struct bpf_map_def SEC(".maps") map_name = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 1,
};
```

#### 4. Program Type Detection

The template handles different eBPF program types:

**XDP Programs**:
```c
extern int xdp_prog(struct xdp_md *ctx);
```

**Kprobe/Kretprobe Programs**:
```c
extern int kprobe_handler(struct pt_regs *ctx);
```

**Tracepoint Programs**:
```c
extern int raw_tp_sys_enter(struct xdp_md *ctx);  // Note: lifter always uses xdp_md*
```

**Important**: The lifter always generates functions with `struct xdp_md*` parameter type, regardless of actual program type. The template must cast context appropriately.

#### 5. Main Function Generation

**XDP Context Setup**:
```c
struct pkt *pkt = malloc(sizeof(struct pkt));
klee_make_symbolic(pkt, sizeof(struct pkt), "constraint_access_user_pkt");
struct xdp_md test;
test.data = (long)(&(pkt->ether));
test.data_end = (long)(pkt + 1);
```

**Kprobe Context Setup**:
```c
struct pt_regs *pt_ctx = malloc(sizeof(struct pt_regs));
klee_make_symbolic(pt_ctx, sizeof(struct pt_regs), "constraint_access_pt_regs");
```

**Tracepoint Context Setup**:
```c
struct pt_regs *tp_regs = malloc(sizeof(struct pt_regs));
klee_make_symbolic(tp_regs, sizeof(struct pt_regs), "constraint_access_tp_regs");

struct {
    __u64 args[6];
} tp_ctx;
tp_ctx.args[0] = (unsigned long)tp_regs;  // pt_regs pointer
klee_make_symbolic(&tp_ctx.args[1], sizeof(__u64), "syscall_id");
// Cast to struct xdp_md* to match lifter's extern type
int val = raw_tp_sys_enter((struct xdp_md *)&tp_ctx);
```

#### 6. Map Initialization

From `program_config.yaml`:
```yaml
map_init:
  - name: my_map
    entries:
      - key: 0
        value: 42
```

Generated code:
```c
__u32 key = 0;
__u32 value = 42;
bpf_map_update_elem(&my_map, &key, &value, BPF_ANY);
```

### Template Generation Process

1. **Parse Program Config** (`generateIR.py::generate_config`):
   - Reads `program_config.yaml`
   - Extracts entry function name
   - Identifies program type
   - Loads map initialization data

2. **Jinja2 Rendering**:
   - Loads `draco_template.j2`
   - Renders with config data
   - Outputs `cpp_generated_code.c`

3. **Compilation**:
   - Compiles template to LLVM IR
   - Applies external symbol pass
   - Links with lifted IR

---

## KLEE Integration

### Custom KLEE Extensions

DRACO-pvt extends KLEE with eBPF-specific verification capabilities.

#### 1. Helper Function Tracking

**Location**: `klee/lib/Core/Executor.cpp`

When `-restrict-helper-function=true`:
```cpp
if(this->restrictBpfHelpers) {
    if(f != nullptr && f->hasName()) {
        const char* name = f->getName().data();
        if(state.entered_main_function)
            state.addHelperFunctionCall(std::string(name));
    }
}
```

**Purpose**: Tracks all helper functions called during execution
**Output**: `helperFunc.results` file listing restricted helpers used

#### 2. Map Access Control

**Verification**: Ensures maps are accessed according to permissions
- `MAP_READ_ONLY`: Only lookups allowed
- `MAP_READ_WRITE`: Lookups and updates allowed
- `MAP_WRITE_ONLY`: Only updates allowed

**Implementation**: Intercepts `bpf_map_lookup_elem` and `bpf_map_update_elem` calls

#### 3. Packet Constraint System

**Location**: `klee/tools/klee/main.cpp`

**Purpose**: Restricts memory access patterns on packet data

**Configuration** (`constraints.json`):
```json
{
  "packet_constraints": [
    {
      "sPort": 80,
      "dPort": "*",
      "sIP": "10.0.0.1",
      "dIP": "*",
      "read-access": [0, 20],
      "write-access": [40, 60]
    }
  ],
  "restricted_helpers": ["bpf_probe_write_user", "bpf_override_return"]
}
```

**Wildcard Support**: `"*"` allows all values/accesses

**Implementation**:
- Parses constraints from JSON
- Applies constraints during symbolic execution
- Validates memory access ranges

#### 4. Two-Phase Execution

**Flag**: `-read-write-two-phase=true`

**Purpose**: Separates read and write phases for map operations
- First phase: All map reads
- Second phase: All map writes

**Implementation**: Uses `__separate()` function calls in template

---

## eBPF-SE: Stubbed Helper Functions

### Overview

eBPF-SE (`ebpf-se/libbpf-stubbed/`) provides KLEE-compatible implementations of eBPF helper functions.

### Architecture

#### 1. Helper Function Detection

Helper functions are conditionally compiled based on usage:
```c
#ifdef USES_BPF_PROBE_READ
static long bpf_probe_read(...) { ... }
#endif
```

The template generator sets these defines based on detected helper usage.

#### 2. Memory Model

**KLEE Address Ranges**:
- **Heap**: `0x40000000 - 0xC0000000` (map values, malloc'd memory)
- **High Memory**: `0x700000000000 - 0x800000000000` (stack, globals)
- **Lifted BPF Stack**: Outside KLEE ranges (typically `0x100 - 0x1000`)

**Address Validation Macros**:
```c
#define IN_KLEE_HEAP(x) ((x) >= 0x40000000ULL && (x) < 0xC0000000ULL)
#define IN_KLEE_HIGH(x) ((x) >= 0x700000000000ULL && (x) < 0x800000000000ULL)
#define IN_KLEE_RANGE(x) (IN_KLEE_HEAP(x) || IN_KLEE_HIGH(x))
```

#### 3. Key Helper Implementations

##### `bpf_probe_read`

**Purpose**: Safely read from kernel memory addresses

**Logic**:
```c
static long bpf_probe_read(void *dst, __u32 size, const void *unsafe_ptr) {
    unsigned long src_val = (unsigned long)unsafe_ptr;
    unsigned long dst_val = (unsigned long)dst;
    int src_valid = IN_KLEE_RANGE(src_val);
    int dst_valid = IN_KLEE_RANGE(dst_val);
    
    if (src_valid) {
        // Source is in KLEE memory (e.g., map value) -> copy it
        if (dst_valid) {
            memcpy(dst, unsafe_ptr, size);
        }
        return 0;
    }
    
    // Source is kernel address -> write symbolic value to destination
    if (!dst_valid) {
        // Destination is lifted BPF stack - can't write from C code
        // Lifted code will use uninitialized (symbolic) values
        return 0;
    }
    
    // Destination is valid KLEE memory - make it symbolic
    if (size == 4) {
        int val;
        klee_make_symbolic(&val, 4, name);
        *(int*)dst = val;
    }
    // ... handle other sizes
}
```

**Challenges**:
- Cannot write to lifted BPF stack addresses from C code
- Kernel addresses are symbolic and outside KLEE ranges
- Solution: Make destination symbolic if in KLEE memory, skip if lifted BPF stack

##### `bpf_probe_write_user`

**Purpose**: Write to user memory (restricted helper)

**Implementation**:
```c
static long bpf_probe_write_user(void *dst, const void *src, __u32 len) {
    // For verification: just return success without actually writing
    // The destination address might be symbolic (from kernel registers),
    // and we only need to detect the use of this restricted function
    (void)dst;
    (void)src;
    (void)len;
    return 0;
}
```

##### `bpf_map_lookup_elem`

**Purpose**: Look up map entries

**Implementation**:
- Maintains array of map stubs
- Allocates memory for map values in KLEE heap
- Returns pointer to value if key exists
- Returns NULL if key doesn't exist

**Map Types Supported**:
- `BPF_MAP_TYPE_ARRAY`
- `BPF_MAP_TYPE_HASH`
- `BPF_MAP_TYPE_PROG_ARRAY` (for tail calls)
- `BPF_MAP_TYPE_RINGBUF`

##### `bpf_get_current_comm`

**Purpose**: Get current process name

**Implementation**:
```c
static long bpf_get_current_comm(void *buf, __u32 size_of_buf) {
    klee_make_symbolic(buf, size_of_buf, "comm");
    return 0;
}
```

Makes the buffer symbolic to explore all possible process names.

#### 4. DRACO_LIFTER_MODE

**Purpose**: Differentiates behavior between direct KLEE compilation and lifted BPF

**Usage**:
```c
#if DRACO_LIFTER_MODE
    // Lifter-specific behavior
    // Handle lifted BPF stack addresses differently
#else
    // Direct KLEE compilation behavior
    // All addresses are in KLEE's managed memory
#endif
```

---

## Verification Workflow

### Complete Pipeline

#### Step 1: Compile eBPF Program
```bash
clang -target bpf -O2 -c program.c -o program.o
```

#### Step 2: Generate IR
```bash
python3 generateIR.py program.o entry_function program_config.yaml
```

This executes:
1. **Lifting**: `bpflifter_cli program.o /tmp/dir`
2. **Optimization**: `opt -O3 -S lifted.ll -o lifted.ll`
3. **Function Pass**: `opt -load libfunc_pass.so -passes=custom-bpf-pass ...`
4. **Template Generation**: Jinja2 rendering
5. **Template Compilation**: `clang -emit-llvm -c template.c`
6. **External Symbol Pass**: `opt -passes=int-to-ext ...`
7. **Linking**: `llvm-link template.bc lifted.bc -o final.bc`

#### Step 3: Run KLEE
```bash
klee \
    -kdalloc -kdalloc-heap-start-address=0x00040000000 -kdalloc-heap-size=1 \
    -libc=uclibc \
    --external-calls=all \
    -solver-backend=z3 \
    -verification=true \
    -read-set=true -write-set=true \
    -restrict-helper-function=true \
    -enable-map-access-control=true \
    -enable-packet-constr=true \
    -config-file=constraints.json \
    final_linked_ir.bc
```

#### Step 4: Analyze Results

**Output Files**:
- `klee-last/helperFunc.results`: Restricted helper usage
- `klee-last/mapAccess.results`: Map access control validation
- `klee-last/*.ktest`: Test cases for each path

### Verification Modes

#### 1. Direct Compilation Mode

**Process**:
- Compile eBPF C source directly with KLEE flags
- All variables in KLEE's managed memory
- Helper stubs can make any variable symbolic

**Advantages**:
- Full symbolic execution
- All paths explorable
- Accurate verification

**Limitations**:
- Requires source code
- Cannot verify pre-compiled eBPF objects

#### 2. Lifted BPF Mode

**Process**:
- Lift eBPF bytecode to LLVM IR
- Generate verification harness
- Link and execute with KLEE

**Advantages**:
- Works with compiled eBPF objects
- No source code required
- Can verify kernel-loaded programs

**Limitations**:
- Cannot write to lifted BPF stack addresses from C stubs
- Some paths may not be explorable if they depend on symbolic values in lifted stack
- Memory model differences between eBPF and KLEE

---

### Constraint System

#### Packet Constraints

**Purpose**: Restrict memory access on packet data

**Example**:
```json
{
  "packet_constraints": [
    {
      "sPort": 80,
      "dPort": "*",
      "read-access": [0, 20],
      "write-access": [40, 60]
    }
  ]
}
```

**Implementation**:
- Parsed in `klee/tools/klee/main.cpp`
- Applied during memory access in `klee/lib/Core/Executor.cpp`
- Wildcard `"*"` allows all values/accesses

#### Helper Function Restrictions

**Configuration**: List of restricted helpers in `constraints.json`

**Detection**: Tracked during execution, reported in `helperFunc.results`

**Example Output**:
```
Restriction on use of helper function : "bpf_probe_write_user"
```

### Symbolic Execution Challenges

#### 1. Lifted BPF Stack Addresses

**Problem**: Cannot write symbolic values to lifted BPF stack from C helper stubs

**Impact**: Variables on lifted stack remain uninitialized (may be treated as 0 or unconstrained)

**Workaround**: 
- Skip writes to lifted BPF stack addresses
- Rely on KLEE's handling of uninitialized values
- Some paths may not be explorable

#### 2. Kernel Register Values

**Problem**: Register values (e.g., `regs->di`) are symbolic kernel addresses

**Solution**: 
- `bpf_probe_read` makes destination symbolic if source is kernel address
- Only works if destination is in KLEE memory
- For lifted BPF stack, values remain uninitialized

#### 3. Pointer Validation

**Problem**: Symbolic pointers can resolve to invalid addresses

**Solution**: 
- Constrain pointers to valid ranges when possible
- Use `klee_assume` to guide exploration
- Handle invalid addresses gracefully in stubs

---

## Known Limitations and Challenges

### 1. Lifted BPF Stack Limitations

**Issue**: Cannot inject symbolic values into lifted BPF stack variables from C code

**Example**: 
```c
// In lifted code:
int read_size;
bpf_probe_read(&read_size, 4, &regs->dx);  // read_size is on lifted stack

// In stub:
// Cannot write to &read_size (address 544) from C code
// read_size remains uninitialized
```

**Impact**: 
- Conditions like `if (read_size != 0x10)` may always fail
- Paths depending on symbolic stack variables may not be explored

**Potential Solutions**:
- Modify lifted IR directly to inject symbolic values
- Use different memory model for lifted BPF
- Allocate lifted stack variables in KLEE heap

### 2. Context Type Mismatch

**Issue**: Lifter always generates functions with `struct xdp_md*` parameter, regardless of program type

**Impact**: 
- Tracepoint programs receive `struct xdp_md*` but expect `struct bpf_raw_tracepoint_args*`
- Must cast context in template

**Workaround**: Cast context to `struct xdp_md*` when calling lifted function

### 3. Map Global Removal

**Issue**: Function pass removes map globals but may miss some cases

**Impact**: 
- Compilation errors if map globals not properly removed
- Map lookups may fail if maps not properly declared

**Mitigation**: 
- Comprehensive map ID → name mapping
- Careful pass ordering
- Validation of generated IR

### 4. Path Exploration

**Issue**: Some execution paths may not be explored due to:
- Uninitialized lifted stack variables
- Constraint solver limitations
- Symbolic pointer resolution

**Impact**: 
- False negatives (missed violations)
- Incomplete path coverage

**Mitigation**: 
- Use multiple solver backends
- Increase exploration time
- Add manual path hints via `klee_assume`

### 5. Helper Function Stubbing

**Issue**: Not all helper functions are fully stubbed

**Impact**: 
- Some helpers may not work correctly in verification
- Missing helpers cause link errors

**Mitigation**: 
- Comprehensive helper function library
- Conditional compilation based on usage
- Fallback to no-op implementations

### Key Files
- **`lifting_tools/generateIR.py`**: Main pipeline orchestrator
- **`lifting_tools/draco_template.j2`**: Verification harness template
- **`bpf_lifter/src/Decompiler.cpp`**: Core lifting implementation
- **`ebpf-se/libbpf-stubbed/src/bpf_helper_defs.h`**: Helper function stubs
- **`klee/lib/Core/Executor.cpp`**: KLEE extensions for eBPF verification