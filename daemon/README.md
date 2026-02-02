# KrakenGuard Daemon

KrakenGuard is a privileged daemon service that provides fine-grained, policy-driven verification of eBPF programs at load time. It uses symbolic execution (KLEE) to explore all program paths and verify compliance with security policies.

## Overview

The daemon accepts eBPF object files from unprivileged clients, verifies them against security policies, and loads verified programs into the kernel on behalf of clients.

## Architecture

- **Verification Pipeline**: Lifts eBPF bytecode to LLVM IR, applies transformations, and runs KLEE symbolic execution
- **BPF Loader**: Loads verified programs into the kernel (currently stub implementation)
- **Unix Socket Interface**: Communicates with clients via Unix domain sockets

## Installation

### Prerequisites

- Docker and docker-compose
- Pre-built binaries:
  - `bpflifter_cli` (from `bpf_lifter/build/`)
  - `klee` (from `klee/build/bin/`)
  - LLVM passes (from `lifting_tools/llvm_*_pass/build/`)

### Build Container

```bash
docker-compose build
```

### Run Daemon

```bash
docker-compose up -d
```

The daemon will listen on `/var/run/krakenguard.sock` (mounted from `./socket`).

## Configuration

Edit `daemon/daemon.yaml` to configure:
- Socket path and permissions
- Tool paths
- KLEE options
- Storage directories

## Usage

### Python Client

```python
from daemon.draco_client import KrakenGuardClient

client = KrakenGuardClient(socket_path="/var/run/krakenguard.sock")

# Load an eBPF program (verify + load)
result = client.load(
    object_file="program.o",
    constraints_file="constraints.json",
    config_file="program_config.yaml",  # optional
    attach_type="xdp",
    attach_target="eth0",
    pin_path="/sys/fs/bpf/my_prog"  # optional
)

if result.status == "success":
    print(f"Program loaded! FD: {result.load_result.program_fd}")
elif result.status == "verification_failed":
    print("Verification failed - program not loaded")
    print(f"Helper functions: {result.verification_result.helper_functions.message}")
    print(f"Map access: {result.verification_result.map_access.message}")

# Verify only (dry-run)
result = client.verify(
    object_file="program.o",
    constraints_file="constraints.json"
)

# Cross-program verification (two eBPF programs linked for analysis)
result = client.verify_cross_program(
    object1_file="katran/balancer_main.o",
    object2_file="electrode/fast_kern.o",
    constraints_file="constraints.json",
    program_config_file="program_config.yaml",
    prog1_func="balancer_ingress",
    prog2_func="fastPaxos_main"
)

# Health check
result = client.health()
```

### Test Client Script

```bash
# Health check
python3 daemon/test_client.py health

# Verify only
python3 daemon/test_client.py verify program.o constraints.json [config.yaml]

# Load (verify + load)
python3 daemon/test_client.py load program.o constraints.json [config.yaml]

# Cross-program verification (equivalent to make cross-program PROG1_OBJ=... PROG2_OBJ=... etc.)
python3 daemon/test_client.py cross-program obj1.o obj2.o constraints.json program_config.yaml prog1_entry prog2_entry [--debug]
```

## Request Format

### Load Request

```json
{
  "version": "1.0",
  "request_id": "uuid",
  "action": "load",
  "retain_results": true,
  "files": {
    "object": {"name": "program.o", "size": 12345, "encoding": "base64"},
    "constraints": {"name": "constraints.json", "size": 456, "encoding": "utf8"},
    "config": {"name": "program_config.yaml", "size": 234, "encoding": "utf8"}
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

### Response Format

```json
{
  "version": "1.0",
  "request_id": "uuid",
  "status": "success|verification_failed|error",
  "verification_result": {
    "passed": true,
    "helper_functions": {"valid": true, "message": "..."},
    "map_access": {"valid": true, "message": "..."}
  },
  "load_result": {
    "loaded": true,
    "program_fd": 42,
    "attach_status": "attached"
  },
  "output": {
    "stdout": "...",
    "stderr": "...",
    "directory": "/data/requests/.../output/klee-out-0",
    "files": {
      "helperFunc.results": "...",
      "mapAccess.results": "..."
    }
  }
}
```

## Protocol

The daemon uses a length-prefixed JSON protocol over Unix domain sockets:

1. **Message Format**: 4-byte length (big-endian) + JSON payload
2. **File Transfer**: After JSON header, files are sent as raw bytes (base64-encoded for binary files)
3. **Sequential Processing**: One request at a time (enforced by lock)

## File Structure

```
/data/requests/<request_id>/
├── input/
│   ├── program.o
│   ├── constraints.json
│   └── program_config.yaml
├── intermediate/
│   ├── lifted.ll
│   └── final_linked_ir.bc
└── output/
    └── klee-out-0/
        ├── helperFunc.results
        ├── mapAccess.results
        └── ...
```

## Logging

Logs are written to `/data/logs/krakenguard.log` (configurable in `daemon.yaml`).

Format: `[timestamp] [level] [component] message`

## Error Codes

| Code | Description |
|------|-------------|
| `LIFT_FAILED` | BPF lifting failed |
| `KLEE_FAILED` | KLEE execution failed |
| `VERIFICATION_FAILED` | Verification completed but policies violated |
| `LOAD_FAILED` | BPF program loading failed |

## Development

### Local Testing

1. Ensure all tools are built and available
2. Update `daemon/daemon.yaml` with correct paths
3. Run daemon: `python3 daemon/krakenguard.py`
4. Test with client: `python3 daemon/test_client.py verify ...`

### Adding New Features

- **BPF Loader**: Implement actual loading in `daemon/loader.py`
- **New Verification Checks**: Add to `daemon/pipeline.py`
- **Protocol Extensions**: Update `daemon/protocol.py`

## Security Considerations

- Daemon runs in privileged container (requires CAP_BPF for loading)
- Socket permissions: 0770 (owner and group only)
- Input validation on all file sizes and paths
- Resource limits enforced (memory, CPU time)

## Troubleshooting

### Socket Permission Denied

Ensure socket directory is writable and has correct permissions:
```bash
chmod 770 /var/run/krakenguard.sock
```

### KLEE Not Found

Check that KLEE binary exists at path specified in `daemon.yaml`:
```bash
ls -la /opt/krakenguard/bin/klee
```

### Pipeline Failures

Check logs for detailed error messages:
```bash
tail -f /data/logs/krakenguard.log
```

## License

See main project LICENSE file.
