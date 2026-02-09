---
name: Convert DRACO-pvt to Daemon
overview: Convert the DRACO-pvt eBPF verification system into a privileged Unix socket-based daemon (KrakenGuard) that accepts object files, configs, and constraints, runs verification, and loads verified programs into the kernel.
todos:
  - id: create-daemon-structure
    content: Create daemon directory structure with __init__.py and empty module files
    status: pending
  - id: create-config-yaml
    content: Create daemon.yaml configuration file with paths and settings
    status: pending
  - id: create-dockerfile-base
    content: Create basic Dockerfile that copies existing binaries (no build yet)
    status: pending
  - id: create-docker-compose
    content: Create docker-compose.yaml with volumes and privileged settings
    status: pending
  - id: implement-config-module
    content: Implement config.py to load daemon.yaml and validate paths
    status: pending
    dependencies:
      - create-config-yaml
  - id: implement-protocol-dataclasses
    content: Implement protocol.py with Request/Response dataclasses
    status: pending
  - id: implement-protocol-serialization
    content: Add JSON serialization and length-prefixed message functions to protocol.py
    status: pending
    dependencies:
      - implement-protocol-dataclasses
  - id: implement-utils-file-manager
    content: Implement utils.py with file management functions (create dirs, cleanup)
    status: pending
  - id: implement-utils-logging
    content: Add structured logging setup to utils.py
    status: pending
    dependencies:
      - implement-utils-file-manager
  - id: implement-loader-stub
    content: Implement loader.py with stub methods that return not-implemented responses
    status: pending
  - id: implement-pipeline-lifting
    content: Implement pipeline.py run_lifting_pipeline() that calls generateIR.py as subprocess
    status: pending
    dependencies:
      - implement-config-module
  - id: implement-pipeline-klee
    content: Add run_klee_verification() to pipeline.py that executes KLEE
    status: pending
    dependencies:
      - implement-pipeline-lifting
  - id: implement-pipeline-results
    content: Add parse_verification_results() and is_verification_passed() to pipeline.py
    status: pending
    dependencies:
      - implement-pipeline-klee
  - id: implement-daemon-socket
    content: Implement krakenguard.py with socket server setup and accept loop
    status: pending
    dependencies:
      - implement-protocol-serialization
      - implement-config-module
  - id: implement-daemon-receive
    content: Add receive_request() and file storage to krakenguard.py
    status: pending
    dependencies:
      - implement-daemon-socket
      - implement-utils-file-manager
  - id: implement-daemon-handler
    content: Add handle_request() that calls pipeline and loader to krakenguard.py
    status: pending
    dependencies:
      - implement-daemon-receive
      - implement-pipeline-results
      - implement-loader-stub
  - id: implement-daemon-response
    content: Add send_response() and result collection to krakenguard.py
    status: pending
    dependencies:
      - implement-daemon-handler
  - id: implement-client-connection
    content: Implement draco_client.py with socket connection and basic send/receive
    status: pending
    dependencies:
      - implement-protocol-serialization
  - id: implement-client-load-method
    content: Add load() method to draco_client.py
    status: pending
    dependencies:
      - implement-client-connection
  - id: implement-client-verify-method
    content: Add verify() and health() methods to draco_client.py
    status: pending
    dependencies:
      - implement-client-load-method
  - id: create-test-client-script
    content: Create test_client.py with example verification requests
    status: pending
    dependencies:
      - implement-client-verify-method
  - id: test-daemon-locally
    content: Test daemon locally before containerization
    status: pending
    dependencies:
      - implement-daemon-response
      - create-test-client-script
  - id: update-dockerfile-full
    content: Update Dockerfile to build all dependencies (multi-stage)
    status: pending
    dependencies:
      - test-daemon-locally
  - id: test-container-build
    content: Build and test Docker container
    status: pending
    dependencies:
      - update-dockerfile-full
  - id: update-readme
    content: Update daemon README with usage instructions
    status: pending
    dependencies:
      - test-container-build
---

# KrakenGuard Daemon Implementation Plan

## Overview

Transform the DRACO-pvt eBPF verification system into a **privileged daemon service** (KrakenGuard) that:

1. Accepts eBPF object files from unprivileged clients
2. Verifies programs against security policies using symbolic execution (KLEE)
3. Loads verified programs into the kernel on behalf of clients
4. Returns verification results, load status, and program FDs

**Important**: All new code goes into the `daemon/` directory. Existing code in `lifting_tools/`, `bpf_lifter/`, `klee/`, etc. is **not modified** - the daemon calls them via subprocess. This ensures the experimental setup remains intact and Docker provides isolation.

## Architecture Summary

```
┌─────────────────────────────────────────────────────────────┐
│           KrakenGuard Daemon (Privileged Container)          │
│                                                             │
│   Client Request → Verification Pipeline → BPF Loader       │
│        │                    │                   │           │
│        │              PASS/FAIL            Load/Skip        │
│        │                    │                   │           │
│        └────────────────────┴───────────────────┘           │
│                             │                               │
│                        Response                             │
│              (verification_result + load_result)            │
└─────────────────────────────────────────────────────────────┘
```

---

## Phase 1: Project Structure

**Goal**: Set up directory structure and configuration files without touching existing code.

### Step 1.1: Create Daemon Directory Structure

Create the following structure:

```
daemon/
├── __init__.py           # Package init
├── krakenguard.py        # Main daemon (empty initially)
├── protocol.py           # Protocol module (empty initially)
├── pipeline.py           # Pipeline wrapper (empty initially)
├── loader.py             # BPF loader stub (empty initially)
├── config.py             # Configuration (empty initially)
├── utils.py              # Utilities (empty initially)
└── draco_client.py       # Client library (empty initially)
```

### Step 1.2: Create Configuration File

Create `daemon/daemon.yaml`:

```yaml
daemon:
  socket_path: /var/run/krakenguard.sock
  socket_permissions: 0770
  log_level: INFO
  log_file: /data/logs/krakenguard.log

paths:
  bpflifter: /opt/krakenguard/bin/bpflifter_cli
  klee: /opt/krakenguard/bin/klee
  opt: /usr/bin/opt
  clang: /usr/bin/clang-13
  llvm_link: /usr/bin/llvm-link
  func_pass: /opt/krakenguard/lib/libfunc_pass.so
  ext_sym_pass: /opt/krakenguard/lib/libext_sym_pass.so
  generate_ir: /opt/krakenguard/lifting_tools/generateIR.py
  templates: /opt/krakenguard/lifting_tools

storage:
  data_dir: /data
  requests_dir: /data/requests

klee:
  heap_start_address: "0x00040000000"
  heap_size: 1
  max_memory: 750000
  solver_backend: z3
  timeout: 300
```

### Step 1.3: Create Basic Dockerfile

Create `Dockerfile` that copies pre-built binaries:

```dockerfile
FROM ubuntu:22.04

# Install runtime dependencies only
RUN apt-get update && apt-get install -y \
    python3 python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Copy pre-built binaries (assumes they exist on host)
COPY bpf_lifter/build/bpflifter_cli /opt/krakenguard/bin/
COPY klee/build/bin/klee /opt/krakenguard/bin/
COPY lifting_tools/ /opt/krakenguard/lifting_tools/
COPY daemon/ /opt/krakenguard/daemon/
# ... more copies

WORKDIR /opt/krakenguard
ENTRYPOINT ["python3", "/opt/krakenguard/daemon/krakenguard.py"]
```

### Step 1.4: Create Docker Compose

Create `docker-compose.yaml`:

```yaml
version: '3.8'
services:
  krakenguard:
    build: .
    container_name: krakenguard
    privileged: true
    volumes:
      - ./socket:/var/run
      - ./data:/data
      - /sys/fs/bpf:/sys/fs/bpf
    restart: unless-stopped
```

---

## Phase 2: Configuration and Protocol

**Goal**: Implement standalone modules that don't depend on the daemon.

### Step 2.1: Implement Config Module

`daemon/config.py`:

- Load `daemon.yaml`
- Validate paths exist
- Provide accessor methods

### Step 2.2: Implement Protocol Dataclasses

`daemon/protocol.py`:

- `Request` dataclass with all fields
- `Response` dataclass with all fields
- `LoadOptions` dataclass
- `VerificationResult` dataclass

### Step 2.3: Implement Protocol Serialization

Add to `daemon/protocol.py`:

- `serialize_message()`: Convert to length-prefixed JSON
- `deserialize_message()`: Parse length-prefixed JSON
- `encode_file()`: Base64 encode binary files
- `decode_file()`: Base64 decode

---

## Phase 3: Utility Functions

**Goal**: Create helper functions for file management and logging.

### Step 3.1: File Manager Functions

`daemon/utils.py`:

- `create_request_directory()`: Create `/data/requests/<id>/input|intermediate|output`
- `cleanup_request_directory()`: Remove directory
- `save_uploaded_file()`: Write file from request to disk

### Step 3.2: Logging Setup

Add to `daemon/utils.py`:

- `setup_logging()`: Configure structured logging
- `get_logger()`: Get logger for component

---

## Phase 4: BPF Loader Stub

**Goal**: Create loader interface with stub implementation.

### Step 4.1: Implement Loader Stub

`daemon/loader.py`:

```python
class BPFLoader:
    def load_program(self, object_file, load_options):
        return {"loaded": False, "program_fd": -1, "message": "stub"}
    
    def attach_program(self, prog_fd, attach_type, target):
        return {"attached": False, "message": "stub"}
    
    def pin_program(self, prog_fd, pin_path):
        return {"pinned": False, "message": "stub"}
```

---

## Phase 5: Pipeline Wrapper

**Goal**: Wrap existing tools via subprocess calls.

### Step 5.1: Implement Lifting Pipeline

`daemon/pipeline.py`:

- `run_lifting_pipeline()`: Call `generateIR.py` via subprocess
- Capture stdout/stderr
- Return path to `final_linked_ir.bc`

### Step 5.2: Implement KLEE Execution

Add to `daemon/pipeline.py`:

- `run_klee_verification()`: Execute KLEE with all flags
- Capture stdout/stderr
- Return KLEE output directory

### Step 5.3: Implement Result Parsing

Add to `daemon/pipeline.py`:

- `parse_verification_results()`: Parse helperFunc.results, mapAccess.results
- `is_verification_passed()`: Return True if both checks pass
- `collect_output_files()`: List all output files

---

## Phase 6: Core Daemon Server

**Goal**: Build the main daemon piece by piece.

### Step 6.1: Socket Server Setup

`daemon/krakenguard.py`:

- Create Unix socket
- Bind and listen
- Accept loop (sequential)

### Step 6.2: Request Receiving

Add to `daemon/krakenguard.py`:

- `receive_request()`: Read and parse request
- `save_request_files()`: Store uploaded files to disk

### Step 6.3: Request Handler

Add to `daemon/krakenguard.py`:

- `handle_request()`: Main request processing
        - Call `run_lifting_pipeline()`
        - Call `run_klee_verification()`
        - Check `is_verification_passed()`
        - If passed, call `loader.load_program()`
        - Collect results

### Step 6.4: Response Sending

Add to `daemon/krakenguard.py`:

- `build_response()`: Create Response object
- `send_response()`: Serialize and send

---

## Phase 7: Client Library

**Goal**: Create client library for easy integration.

### Step 7.1: Connection Handling

`daemon/draco_client.py`:

- `KrakenGuardClient` class
- `connect()` / `disconnect()` methods
- `_send()` / `_receive()` helpers

### Step 7.2: Load Method

Add to `daemon/draco_client.py`:

- `load()`: Send load request with files and options
- Return parsed response

### Step 7.3: Verify and Health Methods

Add to `daemon/draco_client.py`:

- `verify()`: Verify only (dry-run)
- `health()`: Health check request

---

## Phase 8: Testing

**Goal**: Test before containerization.

### Step 8.1: Create Test Script

`daemon/test_client.py`:

- Example verification request
- Print results

### Step 8.2: Local Testing

- Run daemon locally (outside container)
- Run test client
- Verify end-to-end flow

---

## Phase 9: Dockerfile Finalization

**Goal**: Complete containerization.

### Step 9.1: Update Dockerfile

- Multi-stage build (if needed)
- Copy all required files
- Set proper permissions

### Step 9.2: Test Container

- Build container
- Run with docker-compose
- Test from host

---

## Phase 10: Documentation

**Goal**: Document usage.

### Step 10.1: Update README

- Installation instructions
- Usage examples
- API documentation

---

## Files Summary

### New Files (in `daemon/`)

| File | Purpose |

|------|---------|

| `__init__.py` | Package initialization |

| `krakenguard.py` | Main daemon server |

| `protocol.py` | Request/Response protocol |

| `pipeline.py` | Verification pipeline wrapper |

| `loader.py` | BPF loader (stub) |

| `config.py` | Configuration management |

| `utils.py` | Utility functions |

| `draco_client.py` | Client library |

| `daemon.yaml` | Configuration file |

| `test_client.py` | Test script |

### New Files (root)

| File | Purpose |

|------|---------|

| `Dockerfile` | Container build |

| `docker-compose.yaml` | Container orchestration |

### Existing Files (NOT MODIFIED)

| File | Reason |

|------|--------|

| `lifting_tools/generateIR.py` | Called via subprocess |

| `bpf_lifter/*` | Called via subprocess |

| `klee/*` | Called via subprocess |

| `ebpf-se/*` | Used by pipeline |

---

## Success Criteria

1. ✅ Daemon starts and listens on Unix socket
2. ✅ Client can connect and send request
3. ✅ Request files are saved correctly
4. ✅ Pipeline executes (generateIR.py + KLEE)
5. ✅ Results are parsed correctly
6. ✅ Response is sent back to client
7. ✅ Loader stub is called on success
8. ✅ Container builds and runs
9. ✅ Host can communicate with container via socket