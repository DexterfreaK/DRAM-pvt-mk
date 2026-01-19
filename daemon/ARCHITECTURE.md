# KrakenGuard Daemon Architecture

## Overview

KrakenGuard is a **trusted, privileged daemon** that provides fine-grained, policy-driven verification of eBPF programs at load time. It uses symbolic execution (KLEE) to explore all program paths and verify compliance with security policies. Upon successful verification, it loads the eBPF program into the kernel on behalf of unprivileged clients.

The daemon is deployed as a **privileged Docker container** that bundles all required tools and dependencies, exposing a Unix socket interface for client communication.

### Key Principle: Verify-Then-Load

Unprivileged clients delegate eBPF program loading to the KrakenGuard daemon. The daemon:
1. **Verifies** the program against security policies
2. **Loads** the program into the kernel only if verification passes
3. **Returns** the result (and program FD) to the client

This allows unprivileged processes to safely use eBPF while ensuring all programs comply with security policies.

---

## Deployment Model

### Single Daemon Model (Verify + Load)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Host System                                     │
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │           KrakenGuard Daemon (Privileged Container)                    │  │
│  │                                                                        │  │
│  │  ┌──────────────────────────────────────────────────────────────────┐ │  │
│  │  │                      Request Handler                              │ │  │
│  │  └─────────────────────────────┬────────────────────────────────────┘ │  │
│  │                                │                                       │  │
│  │                                ▼                                       │  │
│  │  ┌──────────────────────────────────────────────────────────────────┐ │  │
│  │  │               Verification Pipeline                               │ │  │
│  │  │   BPF Lifter → LLVM Passes → Template → KLEE                      │ │  │
│  │  └─────────────────────────────┬────────────────────────────────────┘ │  │
│  │                                │                                       │  │
│  │                     ┌──────────┴──────────┐                           │  │
│  │                     │                     │                           │  │
│  │               PASS  ▼                     ▼  FAIL                     │  │
│  │  ┌────────────────────────┐    ┌────────────────────────┐            │  │
│  │  │     BPF Loader         │    │     Return Error       │            │  │
│  │  │  (load into kernel)    │    │  (verification failed) │            │  │
│  │  └───────────┬────────────┘    └────────────────────────┘            │  │
│  │              │                                                        │  │
│  │              ▼                                                        │  │
│  │  ┌────────────────────────┐                                          │  │
│  │  │   Return Success       │                                          │  │
│  │  │   + Program FD         │                                          │  │
│  │  └────────────────────────┘                                          │  │
│  │                                                                        │  │
│  │  /var/run/krakenguard.sock  ◄─── Unix Socket                          │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                 │                                           │
│                                 │ Unix Socket                               │
│                                 ▼                                           │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │              Client (Unprivileged)                                     │  │
│  │   - Container runtime, bpfman, application                            │  │
│  │   - Sends: eBPF object + constraints + "load" request                 │  │
│  │   - Receives: verification result + program FD (if passed)            │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Request Flow

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                          Complete Request Flow                                │
│                                                                              │
│  ┌────────────┐       1. Load Request          ┌─────────────────────────┐  │
│  │   Client   │ ─────────────────────────────▶ │   KrakenGuard Daemon    │  │
│  │(unprivileged)│    object.o + constraints    │      (privileged)       │  │
│  └────────────┘                                └───────────┬─────────────┘  │
│                                                            │                 │
│                                                 2. Verify Program            │
│                                                            │                 │
│                                                            ▼                 │
│                                                ┌─────────────────────────┐  │
│                                                │   Verification Result   │  │
│                                                └───────────┬─────────────┘  │
│                                                            │                 │
│                                       ┌────────────────────┴────────────┐   │
│                                       │                                 │   │
│                                 PASS  ▼                           FAIL  ▼   │
│                         ┌─────────────────────┐          ┌──────────────────┐│
│                         │  3. Load Program    │          │   Return Error   ││
│                         │     into Kernel     │          │                  ││
│                         └──────────┬──────────┘          └────────┬─────────┘│
│                                    │                              │          │
│                                    ▼                              │          │
│                         ┌─────────────────────┐                   │          │
│                         │  4. Attach to Hook  │                   │          │
│                         │  (XDP, kprobe, etc) │                   │          │
│                         └──────────┬──────────┘                   │          │
│                                    │                              │          │
│  ┌────────────┐       5. Response  │                              │          │
│  │   Client   │ ◀──────────────────┴──────────────────────────────┘          │
│  │            │    {status, prog_fd, verification_result}                   │
│  └────────────┘                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Why This Design?

1. **Security**: Unprivileged clients cannot load arbitrary eBPF programs
2. **Trust**: Only verified programs are loaded into the kernel
3. **Simplicity**: Single request for verify + load operation
4. **Compliance**: Clear audit trail of what was verified and loaded

---

## High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                     Docker Container (Privileged)                             │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │                      KrakenGuard Daemon                                 │  │
│  │                                                                         │  │
│  │   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐                │  │
│  │   │   Socket    │    │   Request   │    │   Pipeline  │                │  │
│  │   │   Server    │───▶│   Handler   │───▶│   Manager   │                │  │
│  │   └─────────────┘    └─────────────┘    └──────┬──────┘                │  │
│  │                                                │                        │  │
│  │                                                ▼                        │  │
│  │   ┌─────────────────────────────────────────────────────────────────┐  │  │
│  │   │                    Verification Pipeline                         │  │  │
│  │   │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────┐ │  │  │
│  │   │  │  BPF     │  │  LLVM    │  │ Template │  │      KLEE        │ │  │  │
│  │   │  │  Lifter  │─▶│  Passes  │─▶│Generator │─▶│   Execution      │ │  │  │
│  │   │  └──────────┘  └──────────┘  └──────────┘  └──────────────────┘ │  │  │
│  │   └──────────────────────────────────────┬──────────────────────────┘  │  │
│  │                                          │                              │  │
│  │                               ┌──────────┴──────────┐                  │  │
│  │                               │                     │                  │  │
│  │                         PASS  ▼                     ▼ FAIL             │  │
│  │   ┌─────────────────────────────────────┐   ┌───────────────────────┐  │  │
│  │   │           BPF Loader                 │   │    Return Error       │  │  │
│  │   │  ┌──────────┐  ┌──────────────────┐ │   │                       │  │  │
│  │   │  │  Load    │  │  Attach to Hook  │ │   │                       │  │  │
│  │   │  │  Program │─▶│  (XDP, kprobe)   │ │   │                       │  │  │
│  │   │  └──────────┘  └──────────────────┘ │   │                       │  │  │
│  │   └─────────────────────────────────────┘   └───────────────────────┘  │  │
│  │                                                                         │  │
│  │   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐                │  │
│  │   │   Result    │    │    File     │    │   Config    │                │  │
│  │   │  Collector  │    │   Manager   │    │   Manager   │                │  │
│  │   └─────────────┘    └─────────────┘    └─────────────┘                │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │                         Bundled Tools                                   │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌────────────┐  │  │
│  │  │ bpflifter_cli│  │    KLEE      │  │ LLVM/Clang   │  │    Z3      │  │  │
│  │  │              │  │  (modified)  │  │   (v13)      │  │  (solver)  │  │  │
│  │  └──────────────┘  └──────────────┘  └──────────────┘  └────────────┘  │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌────────────┐  │  │
│  │  │ libfunc_pass │  │libext_sym_pas│  │  libbpf-     │  │  libbpf    │  │  │
│  │  │    (.so)     │  │   (.so)      │  │  stubbed     │  │ (loader)   │  │  │
│  │  └──────────────┘  └──────────────┘  └──────────────┘  └────────────┘  │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  /var/run/krakenguard.sock  ◄──────── Unix Socket (exposed to host)         │
│  /data/                     ◄──────── Persistent storage (volume mount)     │
│  /sys/fs/bpf/               ◄──────── BPF filesystem (for pinning)          │
└──────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ Unix Socket
                                    ▼
                    ┌───────────────────────────────┐
                    │    Client (Unprivileged)      │
                    │  (bpfman, container runtime,  │
                    │   application, orchestrator)  │
                    └───────────────────────────────┘
```

---

## Container Structure

### Directory Layout

```
/opt/krakenguard/
├── bin/
│   ├── bpflifter_cli          # eBPF bytecode to LLVM IR lifter
│   ├── klee                   # Symbolic execution engine
│   ├── opt                    # LLVM optimizer
│   ├── clang-13               # Clang compiler
│   ├── llvm-link              # LLVM IR linker
│   └── llvm-dis               # LLVM IR disassembler
│
├── lib/
│   ├── libfunc_pass.so        # LLVM pass for map transformation
│   ├── libext_sym_pass.so     # LLVM pass for external symbols
│   ├── klee-uclibc/           # KLEE's uClibc runtime
│   └── z3/                    # Z3 solver libraries
│
├── include/
│   ├── klee/                  # KLEE headers
│   ├── bpf/                   # BPF headers
│   └── libbpf-stubbed/        # Stubbed helper function headers
│
├── templates/
│   ├── draco_template.j2      # Jinja2 template for verification harness
│   └── draco_cross_prog_template.j2
│
├── daemon/
│   ├── krakenguard.py         # Main daemon process
│   ├── protocol.py            # Socket protocol implementation
│   ├── pipeline.py            # Verification pipeline orchestration
│   ├── loader.py              # BPF loader (stub for now)
│   ├── config.py              # Configuration management
│   └── utils.py               # Utility functions
│
└── config/
    └── daemon.yaml            # Daemon configuration file

/data/                         # Persistent storage (volume mount)
├── requests/                  # Stored verification requests
│   └── <request_id>/
│       ├── input/
│       ├── intermediate/
│       └── output/
└── logs/                      # Daemon logs
    └── krakenguard.log

/var/run/krakenguard.sock      # Unix domain socket
```

---

## Component Details

### 1. Socket Server

**Responsibilities:**
- Listen on Unix domain socket
- Accept incoming connections
- Enforce sequential processing (one request at a time)
- Handle connection lifecycle

**Implementation:**
```python
# Pseudocode
class SocketServer:
    def __init__(self, socket_path="/var/run/krakenguard.sock"):
        self.socket_path = socket_path
        self.processing_lock = threading.Lock()  # Ensures sequential processing
    
    def start(self):
        # Create and bind socket
        # Listen for connections
        # For each connection, handle in sequence
```

### 2. Request Handler

**Responsibilities:**
- Parse incoming request protocol
- Validate request data
- Extract files from request
- Dispatch to pipeline manager
- Format and send response

**Request Processing Flow:**
```
┌─────────────────────────────────────────────────────────────────┐
│                    Request Handler Flow                         │
│                                                                 │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐  │
│  │ Receive  │    │ Validate │    │  Store   │    │ Dispatch │  │
│  │ Request  │───▶│  & Parse │───▶│  Files   │───▶│   to     │  │
│  │          │    │          │    │          │    │ Pipeline │  │
│  └──────────┘    └──────────┘    └──────────┘    └────┬─────┘  │
│                                                        │        │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐         │        │
│  │  Send    │    │  Format  │    │ Collect  │◀────────┘        │
│  │ Response │◀───│ Response │◀───│ Results  │                  │
│  └──────────┘    └──────────┘    └──────────┘                  │
└─────────────────────────────────────────────────────────────────┘
```

### 3. Pipeline Manager

**Responsibilities:**
- Orchestrate verification pipeline stages
- Manage intermediate files
- Capture stdout/stderr from each stage
- Handle stage failures gracefully

**Pipeline Stages:**
```
┌──────────────────────────────────────────────────────────────────────────┐
│                        Verification Pipeline                              │
│                                                                          │
│  Stage 1: BPF Lifting                                                    │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │  Input: program.o                                                    │ │
│  │  Tool: bpflifter_cli                                                 │ │
│  │  Output: lifted.ll, map_dump, prog_dump                              │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
│                              │                                            │
│                              ▼                                            │
│  Stage 2: LLVM Optimization                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │  Input: lifted.ll                                                    │ │
│  │  Tool: opt -O3                                                       │ │
│  │  Output: lifted_opt.ll                                               │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
│                              │                                            │
│                              ▼                                            │
│  Stage 3: Relocation Analysis                                            │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │  Input: program.o (ELF)                                              │ │
│  │  Tool: Python ELF parser                                             │ │
│  │  Output: map_offset_mapping                                          │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
│                              │                                            │
│                              ▼                                            │
│  Stage 4: LLVM Function Pass                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │  Input: lifted_opt.ll, map_offset_mapping                            │ │
│  │  Tool: opt -load libfunc_pass.so                                     │ │
│  │  Output: lifted_transformed.ll                                       │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
│                              │                                            │
│                              ▼                                            │
│  Stage 5: Template Generation                                            │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │  Input: map_dump, prog_dump, program_config.yaml                     │ │
│  │  Tool: Jinja2 template renderer                                      │ │
│  │  Output: cpp_generated_code.c                                        │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
│                              │                                            │
│                              ▼                                            │
│  Stage 6: Template Compilation                                           │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │  Input: cpp_generated_code.c                                         │ │
│  │  Tool: clang-13 -emit-llvm                                           │ │
│  │  Output: cpp_generated_code.bc                                       │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
│                              │                                            │
│                              ▼                                            │
│  Stage 7: External Symbol Pass (optional)                                │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │  Input: cpp_generated_code.bc                                        │ │
│  │  Tool: opt -load libext_sym_pass.so                                  │ │
│  │  Output: cpp_generated_code_ext.bc                                   │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
│                              │                                            │
│                              ▼                                            │
│  Stage 8: IR Linking                                                     │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │  Input: cpp_generated_code.bc, lifted_transformed.ll                 │ │
│  │  Tool: llvm-link                                                     │ │
│  │  Output: final_linked_ir.bc                                          │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
│                              │                                            │
│                              ▼                                            │
│  Stage 9: KLEE Symbolic Execution                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │  Input: final_linked_ir.bc, constraints.json                         │ │
│  │  Tool: klee (with custom extensions)                                 │ │
│  │  Output: klee-out-N/ (helperFunc.results, mapAccess.results, etc.)   │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────────┘
```

### 4. Result Collector

**Responsibilities:**
- Locate KLEE output directory (klee-last symlink)
- Parse verification result files
- Determine pass/fail status
- Collect file paths for response
- Handle cleanup based on client preference

**Output Files Collected:**
| File | Description |
|------|-------------|
| `helperFunc.results` | Restricted helper function usage |
| `mapAccess.results` | Map access control validation |
| `info` | KLEE execution information |
| `warnings.txt` | KLEE warnings |
| `messages.txt` | KLEE messages |
| `*.ktest` | Test cases for each explored path |

**Verification Decision:**
```
┌─────────────────────────────────────────────────────────────────┐
│                 Verification Decision Logic                      │
│                                                                 │
│  helper_functions.valid AND map_access.valid                   │
│                    │                                            │
│         ┌─────────┴─────────┐                                  │
│         │                   │                                  │
│    true ▼              false ▼                                 │
│  ┌──────────────┐   ┌──────────────┐                          │
│  │  PASS        │   │  FAIL        │                          │
│  │  → Load BPF  │   │  → Return    │                          │
│  │    program   │   │    error     │                          │
│  └──────────────┘   └──────────────┘                          │
└─────────────────────────────────────────────────────────────────┘
```

### 5. File Manager

**Responsibilities:**
- Create and manage request directories
- Store input files securely
- Manage intermediate files
- Handle cleanup or persistence based on client preference

**Directory Lifecycle:**
```
Request Received
      │
      ▼
┌─────────────────────┐
│ Create request dir  │
│ /data/requests/<id>/│
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ Store input files   │
│ input/program.o     │
│ input/constraints.  │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ Pipeline execution  │
│ intermediate/...    │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ KLEE output         │
│ output/klee-out-N/  │
└──────────┬──────────┘
           │
           ▼
    ┌──────┴──────┐
    │             │
    ▼             ▼
┌────────┐   ┌────────┐
│ Keep   │   │ Delete │
│(client │   │(client │
│ option)│   │ option)│
└────────┘   └────────┘
```

### 6. BPF Loader

**Responsibilities:**
- Load verified eBPF programs into the kernel
- Attach programs to hooks (XDP, kprobe, tracepoint, etc.)
- Pin programs to BPF filesystem
- Return program file descriptors to clients

**Note:** Currently implemented as a **stub** - actual loading not yet implemented.

**Stub Implementation (`daemon/loader.py`):**
```python
class BPFLoader:
    """
    BPF Loader - loads verified eBPF programs into the kernel.
    
    STUB IMPLEMENTATION: Actual loading not yet implemented.
    Will use libbpf or bcc to load programs in the future.
    """
    
    def load_program(self, object_file: str, load_options: dict) -> dict:
        """
        Load a verified eBPF program into the kernel.
        
        Args:
            object_file: Path to verified .o file
            load_options: Attachment options (type, target, pin_path)
            
        Returns:
            dict with load status, program_fd, etc.
        """
        # STUB: Actual loading not implemented
        return {
            "loaded": False,
            "program_fd": -1,
            "attach_status": "stub_not_implemented",
            "message": "BPF loading not yet implemented - stub only"
        }
    
    def attach_program(self, prog_fd: int, attach_type: str, target: str) -> dict:
        """Attach program to hook - stub."""
        return {
            "attached": False,
            "message": "stub_not_implemented"
        }
    
    def pin_program(self, prog_fd: int, pin_path: str) -> dict:
        """Pin program to bpffs - stub."""
        return {
            "pinned": False,
            "message": "stub_not_implemented"
        }
    
    def unload_program(self, prog_fd: int) -> dict:
        """Unload/close program - stub."""
        return {
            "unloaded": False,
            "message": "stub_not_implemented"
        }
```

**Future Implementation:**
When fully implemented, the loader will:
1. Use `libbpf` (via Python bindings or subprocess) to load programs
2. Handle map creation and initialization
3. Attach to appropriate hooks based on program type
4. Support pinning for persistent programs
5. Return file descriptors for client management

### 7. Config Manager

**Responsibilities:**
- Load daemon configuration from file
- Manage tool paths
- Set environment variables
- Provide KLEE options

**Configuration File (`daemon.yaml`):**
```yaml
daemon:
  socket_path: /var/run/krakenguard.sock
  socket_permissions: 0770
  log_level: INFO
  log_file: /data/logs/krakenguard.log

paths:
  bpflifter: /opt/krakenguard/bin/bpflifter_cli
  klee: /opt/krakenguard/bin/klee
  opt: /opt/krakenguard/bin/opt
  clang: /opt/krakenguard/bin/clang-13
  llvm_link: /opt/krakenguard/bin/llvm-link
  func_pass: /opt/krakenguard/lib/libfunc_pass.so
  ext_sym_pass: /opt/krakenguard/lib/libext_sym_pass.so
  templates: /opt/krakenguard/templates
  klee_uclibc: /opt/krakenguard/lib/klee-uclibc

klee:
  heap_start_address: "0x00040000000"
  heap_size: 1
  max_memory: 750000
  solver_backend: z3
  search_strategy: dfs

storage:
  data_dir: /data
  requests_dir: /data/requests
  default_retention: cleanup  # 'cleanup' or 'persist'
```

---

## Communication Protocol

### Message Format

All messages use a length-prefixed JSON format:

```
┌─────────────────────────────────────────────────────────────┐
│                      Message Structure                       │
├──────────────┬──────────────────────────────────────────────┤
│  4 bytes     │  N bytes                                     │
│  (uint32)    │  (JSON payload)                              │
│  Length      │  Message body                                │
└──────────────┴──────────────────────────────────────────────┘
```

### Request Message

```json
{
  "version": "1.0",
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "action": "load",
  "retain_results": true,
  "files": {
    "object": {
      "name": "program.o",
      "size": 12345,
      "encoding": "base64"
    },
    "constraints": {
      "name": "constraints.json",
      "size": 456,
      "encoding": "utf8"
    },
    "config": {
      "name": "program_config.yaml",
      "size": 234,
      "encoding": "utf8"
    }
  },
  "options": {
    "entry_function": "xdp_prog",
    "timeout": 300
  },
  "load_options": {
    "attach_type": "xdp",
    "attach_target": "eth0",
    "pin_path": "/sys/fs/bpf/my_prog"
  }
}
```

**Action Types:**
| Action | Description |
|--------|-------------|
| `load` | Verify program, then load into kernel if verification passes (default) |
| `verify` | Verify program only, do not load (for testing/dry-run) |
| `health` | Health check request (no files required) |
```

**File Data:**
After the JSON header, file contents are sent:
```
┌──────────────────────────────────────────────────┐
│  JSON header (length-prefixed)                   │
├──────────────────────────────────────────────────┤
│  File 1: object file (base64 or raw bytes)       │
├──────────────────────────────────────────────────┤
│  File 2: constraints.json (UTF-8 text)           │
├──────────────────────────────────────────────────┤
│  File 3: program_config.yaml (UTF-8 text, opt)   │
└──────────────────────────────────────────────────┘
```

### Response Message

**Success Response (action: load):**
```json
{
  "version": "1.0",
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "success",
  "verification_result": {
    "passed": true,
    "helper_functions": {
      "valid": true,
      "message": "No use of restricted function detected"
    },
    "map_access": {
      "valid": true,
      "message": "Map Access control : VALID"
    }
  },
  "load_result": {
    "loaded": true,
    "program_fd": 42,
    "attach_status": "attached",
    "attach_target": "eth0",
    "pin_path": "/sys/fs/bpf/my_prog"
  },
  "execution": {
    "duration_seconds": 12.5,
    "paths_explored": 42,
    "return_code": 0
  },
  "output": {
    "stdout": "...",
    "stderr": "...",
    "directory": "/data/requests/550e8400.../output/klee-out-0",
    "files": {
      "helperFunc.results": "/data/requests/.../output/klee-out-0/helperFunc.results",
      "mapAccess.results": "/data/requests/.../output/klee-out-0/mapAccess.results",
      "info": "/data/requests/.../output/klee-out-0/info"
    }
  },
  "retained": true
}
```

**Verification Failed Response:**
```json
{
  "version": "1.0",
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "verification_failed",
  "verification_result": {
    "passed": false,
    "helper_functions": {
      "valid": false,
      "message": "Restriction on use of helper function: bpf_probe_write_user"
    },
    "map_access": {
      "valid": true,
      "message": "Map Access control : VALID"
    }
  },
  "load_result": {
    "loaded": false,
    "reason": "Verification failed - program not loaded"
  },
  "output": {
    "stdout": "...",
    "stderr": "...",
    "directory": "/data/requests/550e8400.../output/klee-out-0"
  },
  "retained": true
}
```

**Error Response (pipeline error):**
```json
{
  "version": "1.0",
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "error",
  "error": {
    "stage": "lifting",
    "code": "LIFT_FAILED",
    "message": "Failed to lift eBPF bytecode",
    "details": "Invalid ELF format"
  },
  "load_result": {
    "loaded": false,
    "reason": "Pipeline error - program not loaded"
  },
  "output": {
    "stdout": "...",
    "stderr": "...",
    "directory": "/data/requests/550e8400.../intermediate"
  },
  "retained": true
}
```

### Protocol State Machine

```
┌─────────────────────────────────────────────────────────────────┐
│                    Protocol State Machine                        │
│                                                                 │
│  ┌──────────┐                                                   │
│  │  IDLE    │◀───────────────────────────────────────────┐      │
│  └────┬─────┘                                            │      │
│       │ Client connects                                  │      │
│       ▼                                                  │      │
│  ┌──────────┐                                            │      │
│  │CONNECTED │                                            │      │
│  └────┬─────┘                                            │      │
│       │ Receive header                                   │      │
│       ▼                                                  │      │
│  ┌──────────┐     Invalid header    ┌──────────┐        │      │
│  │ HEADER   │─────────────────────▶│  ERROR   │────────┘      │
│  │ RECEIVED │                       └──────────┘               │
│  └────┬─────┘                                                  │
│       │ Valid header, receive files                            │
│       ▼                                                        │
│  ┌──────────┐     File error        ┌──────────┐              │
│  │RECEIVING │─────────────────────▶│  ERROR   │───────────────┤
│  │  FILES   │                       └──────────┘              │
│  └────┬─────┘                                                  │
│       │ All files received                                     │
│       ▼                                                        │
│  ┌──────────┐     Pipeline error    ┌──────────┐              │
│  │PROCESSING│─────────────────────▶│  ERROR   │───────────────┤
│  │          │                       └──────────┘              │
│  └────┬─────┘                                                  │
│       │ Pipeline complete                                      │
│       ▼                                                        │
│  ┌──────────┐                                                  │
│  │ SENDING  │                                                  │
│  │ RESPONSE │──────────────────────────────────────────────────┘
│  └──────────┘                                                   │
└─────────────────────────────────────────────────────────────────┘
```

---

## Docker Deployment

### Dockerfile Structure

```dockerfile
# Multi-stage build for KrakenGuard daemon

# Stage 1: Build LLVM/Clang
FROM ubuntu:22.04 AS llvm-builder
# ... build LLVM 15

# Stage 2: Build Z3
FROM ubuntu:22.04 AS z3-builder
# ... build Z3

# Stage 3: Build KLEE
FROM ubuntu:22.04 AS klee-builder
# ... build KLEE with modifications

# Stage 4: Build BPF Lifter
FROM ubuntu:22.04 AS lifter-builder
# ... build bpflifter_cli

# Stage 5: Build LLVM Passes
FROM ubuntu:22.04 AS passes-builder
# ... build libfunc_pass.so and libext_sym_pass.so

# Final Stage: Runtime image
FROM ubuntu:22.04

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    python3 python3-pip \
    libc6 libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

# Copy built binaries from builder stages
COPY --from=llvm-builder /usr/local/bin/opt /opt/krakenguard/bin/
COPY --from=llvm-builder /usr/local/bin/clang-13 /opt/krakenguard/bin/
COPY --from=llvm-builder /usr/local/bin/llvm-link /opt/krakenguard/bin/
COPY --from=z3-builder /usr/local/lib/libz3.so* /opt/krakenguard/lib/
COPY --from=klee-builder /usr/local/bin/klee /opt/krakenguard/bin/
COPY --from=klee-builder /usr/local/lib/klee/ /opt/krakenguard/lib/klee-uclibc/
COPY --from=lifter-builder /build/bpflifter_cli /opt/krakenguard/bin/
COPY --from=passes-builder /build/*.so /opt/krakenguard/lib/

# Copy daemon code and templates
COPY daemon/ /opt/krakenguard/daemon/
COPY lifting_tools/draco_template.j2 /opt/krakenguard/templates/
COPY ebpf-se/libbpf-stubbed/ /opt/krakenguard/include/libbpf-stubbed/
COPY examples/headers/ /opt/krakenguard/include/headers/

# Install Python dependencies
RUN pip3 install jinja2 pyyaml pyelftools

# Create data directory
RUN mkdir -p /data/requests /data/logs

# Set environment
ENV KRAKENGUARD_HOME=/opt/krakenguard
ENV PATH="${KRAKENGUARD_HOME}/bin:${PATH}"
ENV LD_LIBRARY_PATH="${KRAKENGUARD_HOME}/lib:${LD_LIBRARY_PATH}"

# Expose socket location
VOLUME ["/var/run", "/data"]

# Run daemon
ENTRYPOINT ["python3", "/opt/krakenguard/daemon/krakenguard.py"]
```

### Docker Compose

```yaml
version: '3.8'

services:
  krakenguard:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: krakenguard
    # Privileged mode required for eBPF loading
    privileged: true
    # Alternative: Use specific capabilities instead of full privileged mode
    # cap_add:
    #   - SYS_ADMIN
    #   - BPF
    #   - NET_ADMIN
    #   - PERFMON
    volumes:
      - krakenguard-socket:/var/run
      - krakenguard-data:/data
      - /sys/fs/bpf:/sys/fs/bpf        # BPF filesystem for pinning
      - /sys/kernel/debug:/sys/kernel/debug:ro  # For BTF access
    restart: unless-stopped
    # Resource limits
    deploy:
      resources:
        limits:
          memory: 8G
          cpus: '4'

volumes:
  krakenguard-socket:
  krakenguard-data:
```

---

## Security Considerations

### Socket Security
- Socket file permissions: `0770` (owner and group only)
- Container runs as non-root user
- Socket accessible only to authorized clients

### Input Validation
- File size limits (prevent DoS)
- File type validation (must be valid ELF for object files)
- JSON schema validation for config files
- Path traversal prevention

### Resource Limits
- Memory limits per verification request
- CPU time limits (KLEE timeout)
- Disk space limits for results

### Isolation
- Each request runs in isolated directory
- No cross-request data access
- Cleanup of sensitive intermediate files

---

## Error Handling

### Error Categories

| Category | Code Range | Description |
|----------|------------|-------------|
| Protocol | 1xxx | Protocol/communication errors |
| Input | 2xxx | Invalid input files |
| Pipeline | 3xxx | Verification pipeline failures |
| Resource | 4xxx | Resource exhaustion |
| Internal | 5xxx | Internal daemon errors |

### Error Codes

| Code | Name | Description |
|------|------|-------------|
| 1001 | `PROTOCOL_VERSION_MISMATCH` | Unsupported protocol version |
| 1002 | `INVALID_MESSAGE` | Malformed message |
| 2001 | `INVALID_OBJECT_FILE` | Invalid eBPF object file |
| 2002 | `INVALID_CONSTRAINTS` | Invalid constraints.json |
| 2003 | `MISSING_REQUIRED_FILE` | Required file not provided |
| 3001 | `LIFT_FAILED` | BPF lifting failed |
| 3002 | `PASS_FAILED` | LLVM pass failed |
| 3003 | `COMPILE_FAILED` | Template compilation failed |
| 3004 | `LINK_FAILED` | IR linking failed |
| 3005 | `KLEE_FAILED` | KLEE execution failed |
| 3006 | `KLEE_TIMEOUT` | KLEE execution timeout |
| 3007 | `VERIFICATION_FAILED` | Verification completed but policies violated |
| 3008 | `LOAD_FAILED` | BPF program loading failed |
| 3009 | `ATTACH_FAILED` | BPF program attachment failed |
| 3010 | `PIN_FAILED` | BPF program pinning failed |
| 4001 | `OUT_OF_MEMORY` | Memory limit exceeded |
| 4002 | `DISK_FULL` | Disk space exhausted |
| 5001 | `INTERNAL_ERROR` | Unexpected internal error |

---

## Logging

### Log Format
```
[timestamp] [level] [request_id] [component] message
```

### Example Log
```
[2026-01-19T10:30:45Z] [INFO] [550e8400] [socket] Client connected
[2026-01-19T10:30:45Z] [INFO] [550e8400] [handler] Request received: verify
[2026-01-19T10:30:45Z] [DEBUG] [550e8400] [file_mgr] Created directory: /data/requests/550e8400
[2026-01-19T10:30:46Z] [INFO] [550e8400] [pipeline] Stage 1/9: BPF Lifting
[2026-01-19T10:30:47Z] [INFO] [550e8400] [pipeline] Stage 2/9: LLVM Optimization
...
[2026-01-19T10:31:02Z] [INFO] [550e8400] [pipeline] Stage 9/9: KLEE Execution
[2026-01-19T10:31:15Z] [INFO] [550e8400] [result] Verification passed
[2026-01-19T10:31:15Z] [INFO] [550e8400] [socket] Response sent, connection closed
```

---

## Monitoring and Health

### Health Check Endpoint
The daemon supports a simple health check via a special request:

```json
{
  "action": "health"
}
```

Response:
```json
{
  "status": "healthy",
  "uptime_seconds": 3600,
  "requests_processed": 42,
  "current_request": null,
  "disk_usage_mb": 1024,
  "version": "1.0.0"
}
```

### Metrics (Optional)
- Requests per minute
- Average verification time
- Success/failure rate
- Resource utilization

---

## Client Integration

### Python Client Example

```python
from krakenguard import KrakenGuardClient

client = KrakenGuardClient(socket_path="/var/run/krakenguard.sock")

# Load an eBPF program (verify + load)
result = client.load(
    object_file="program.o",
    constraints="constraints.json",
    config="program_config.yaml",  # optional
    attach_type="xdp",
    attach_target="eth0",
    pin_path="/sys/fs/bpf/my_prog",  # optional
    retain_results=True,
    timeout=300
)

if result.status == "success":
    print(f"Program loaded successfully!")
    print(f"Program FD: {result.load_result.program_fd}")
    print(f"Attached to: {result.load_result.attach_target}")
elif result.status == "verification_failed":
    print(f"Verification failed: {result.verification_result}")
    print(f"Program was NOT loaded into kernel")
else:
    print(f"Error: {result.error}")

# Verify only (dry-run, no load)
result = client.verify(
    object_file="program.o",
    constraints="constraints.json",
    retain_results=True
)

if result.verification_result.passed:
    print("Verification passed - program is safe to load")
else:
    print("Verification failed - program violates policies")
```

### CLI Example

```bash
# Load an eBPF program (verify + load)
krakenguard-cli load \
    --object program.o \
    --constraints constraints.json \
    --config program_config.yaml \
    --attach-type xdp \
    --attach-target eth0 \
    --pin /sys/fs/bpf/my_prog \
    --retain

# Verify only (dry-run)
krakenguard-cli verify \
    --object program.o \
    --constraints constraints.json \
    --retain

# Check daemon health
krakenguard-cli health

# List loaded programs (future)
krakenguard-cli list
```

### Integration with bpfman

KrakenGuard can integrate with bpfman as a verification layer:

```
┌─────────────┐      ┌─────────────────┐      ┌─────────────┐
│  User       │      │    bpfman       │      │ KrakenGuard │
│  Request    │─────▶│  (eBPF manager) │─────▶│   Daemon    │
└─────────────┘      └────────┬────────┘      └──────┬──────┘
                              │                      │
                              │  If verification     │
                              │  passes              │
                              │◀─────────────────────┘
                              │
                              ▼
                     ┌─────────────────┐
                     │  Kernel (eBPF)  │
                     └─────────────────┘
```
