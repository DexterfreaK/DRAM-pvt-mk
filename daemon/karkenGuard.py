#!/usr/bin/env python3

import os
import socket
import subprocess
import threading
import tempfile
import glob
import shutil
import time

SOCKET_PATH = "/tmp/ebpf_verifier.sock"
VERIFY_BINARY = "/opt/ebpf-daemon/verifier_binary"
PATH_TO_SHELL_SCRIPT = "/home/jainil/Draco/DRACO-verifier/paths.sh"
LIFTING_TOOLS_DIR = "/home/jainil/Draco/DRACO-verifier/lifting_tools"
KLEE_BPF_CFLAGS = "-I/home/jainil/Draco/DRACO-verifier/examples/headers/ -I/usr/include/x86_64-linux-gnu -I/home/jainil/Draco/DRACO-verifier/ebpf-se/libbpf-stubbed/src/build/usr/include/"

def copy_folder_contents(src, dst):
    for item in glob.glob(os.path.join(src, "*")):
        if os.path.isdir(item):
            shutil.copytree(item, os.path.join(dst, os.path.basename(item)))
        else:
            shutil.copy2(item, dst)

def source_and_load_env(path_to_sh):
    command = ['bash', '-c', f'source "{path_to_sh}" && env']
    result = subprocess.run(command, capture_output=True, text=True, check=True)

    for line in result.stdout.splitlines():
        if '=' in line:
            key, val = line.split('=', 1)
            os.environ[key] = val

def is_klee_output_valid(temp_dir):
    try:
        map_results_file = os.path.join(temp_dir, "klee-last", "mapAccess.results")
        helper_results_file = os.path.join(temp_dir, "klee-last", "helperFunc.results")
        if not os.path.exists(map_results_file) or not os.path.exists(helper_results_file):
            print("DEBUG: KLEE output files not found")
            return False
        
        with open(map_results_file, 'r') as f:
            map_results = f.read().strip()
            if "Map Access control : VALID" not in map_results:
                print("DEBUG: Map access control validation failed : ", map_results)
                return False
        
        with open(helper_results_file, 'r') as f:
            helper_results = f.read().strip()
            if "No use of restricted function detected in any execution path" not in helper_results:
                print("DEBUG: Helper function restriction validation failed : ", helper_results)
                return False
        
        return True

    except Exception as e:
        print(f"DEBUG: Exception occurred in process_klee_output: {e}")
        return False

def handle_source(temp_dir, file_name, conn):
    try:
        ebpf_file = os.path.join(temp_dir, file_name)
        json_file = os.path.join(temp_dir, "constraints.json")

        if not os.path.exists(ebpf_file) or not os.path.exists(json_file):
            conn.sendall(b"ERROR: eBPF source or JSON file not found\n")
            return

        bc_file = os.path.join(temp_dir, "main.bc")
        clang_cmd = [
            "clang-13", "-target", "bpf", "-DKLEE_VERIFICATION", "-DVERIFY_INTERACTIONS"
        ] + KLEE_BPF_CFLAGS.strip().split() + [
            "-I", os.environ["KLEE_INCLUDE"],
            "-D__USE_VMLINUX__", "-D__TARGET_ARCH_x86",
            "-DBPF_NO_PRESERVE_ACCESS_INDEX", "-Wall",
            "-Wno-unused-value", "-Wno-unused-variable",
            "-Wno-pointer-sign", "-Wno-compare-distinct-pointer-types",
            "-Werror", "-fno-discard-value-names", "-fno-builtin",
            "-O0", "-emit-llvm", "-c", "-g", ebpf_file,
            "-o", bc_file
        ]

        result = subprocess.run(clang_cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print("DEBUG: clang stderr:", result.stderr)
            conn.sendall(b"ERROR: clang compilation failed\n" + result.stderr.encode())
            return

        subprocess.run(["llvm-dis", "-show-annotations", bc_file], check=False)

        klee_cmd = [
            "taskset", "-c", "6", "klee", "-kdalloc",
            "-kdalloc-heap-start-address=0x00040000000", "-kdalloc-heap-size=1",
            "-libc=uclibc", "--external-calls=all", "--disable-verify",
            "-solver-backend=z3", "-silent-klee-assume=true", "--exit-on-error",
            "-max-memory=750000", "-search=dfs", "-single-object-resolution=true",
            "-verification=true", "-read-set=true", "-write-set=true",
            "-map-correlation=true", "-restrict-helper-function=true",
            "-enable-map-access-control=true", "-enable-packet-constr=true",
            f"-config-file={json_file}", bc_file
        ]

        print("DEBUG: Running KLEE:", " ".join(klee_cmd))
        result = subprocess.run(klee_cmd, capture_output=True, text=True)

        if result.returncode == 0 and is_klee_output_valid(temp_dir):
            conn.sendall(b"SUCCESS: verification passed\n")
        else:
            conn.sendall(b"FAIL: klee returned non-zero\n" + result.stderr.encode())

    except Exception as e:
        print(f"DEBUG: Exception occurred in handle_source: {e}")
        conn.sendall(f"ERROR: {str(e)}\n".encode())

def handle_object(temp_dir, file_name, conn):
    try:
        object_file = os.path.join(temp_dir, file_name)
        json_file = os.path.join(temp_dir, "constraints.json")
        if not os.path.exists(object_file):
            conn.sendall(b"ERROR: main.o not found\n")
            return

        ir_py = os.path.join(LIFTING_TOOLS_DIR, "generateIR.py")
        print(f"DEBUG: Running generateIR.py: {ir_py} {object_file}")
        result = subprocess.run(["python3", ir_py, object_file], capture_output=True, text=True)
        if result.returncode != 0:
            print("DEBUG: generateIR.py stderr:", result.stderr)
            conn.sendall(b"ERROR: generateIR.py failed\n" + result.stderr.encode())
            return

        bc_file = os.path.join(temp_dir, "final_linked_ir.bc")
        print(f"DEBUG: Running llvm-dis on {bc_file}")
        subprocess.run(["llvm-dis", "-show-annotations", bc_file], check=False)

        klee_cmd = [
            "taskset", "-c", "6", "klee", "-kdalloc",
            "-kdalloc-heap-start-address=0x00040000000", "-kdalloc-heap-size=1",
            "-libc=uclibc", "--external-calls=all", "--disable-verify",
            "-solver-backend=z3", "-silent-klee-assume=true", "--exit-on-error",
            "-max-memory=750000", "-search=dfs", "-single-object-resolution=true",
            "-verification=true", "-read-set=true", "-write-set=true",
            "-map-correlation=true", "-restrict-helper-function=true",
            "-enable-map-access-control=true", "-enable-packet-constr=true",
            f"-config-file={json_file}", bc_file
        ]

        print("DEBUG: Running KLEE:", " ".join(klee_cmd))
        result = subprocess.run(klee_cmd, capture_output=True, text=True)
        print("DEBUG: KLEE stdout:", result.stdout)
        print("DEBUG: KLEE stderr:", result.stderr)
        print(f"DEBUG: KLEE return code: {result.returncode}")

        if result.returncode == 0:
            conn.sendall(b"SUCCESS: verification passed\n")
        else:
            conn.sendall(b"FAIL: klee returned non-zero\n" + result.stderr.encode())

    except Exception as e:
        print(f"DEBUG: Exception occurred in handle_object: {e}")
        conn.sendall(f"ERROR: {str(e)}\n".encode())

def handle_client(conn):
    try:
        print("DEBUG: New client connected")
        data = conn.recv(4096).decode().strip()
        lines = data.splitlines()
        if len(lines) < 3:
            conn.sendall(b"ERROR: Expected eBPF program folder, file name and type of input\n")
            return

        ebpf_folder, file_name, input_type = lines[0], lines[1], lines[2]
        print(f"DEBUG: Received folder={ebpf_folder}, type={input_type}")

        if not os.path.exists(ebpf_folder) or not os.path.isdir(ebpf_folder):
            conn.sendall(b"ERROR: project folder not found\n")
            return

        with tempfile.TemporaryDirectory() as temp_dir:
            print(f"DEBUG: Created temp directory: {temp_dir}")
            copy_folder_contents(ebpf_folder, temp_dir)

            if input_type == "source":
                handle_source(temp_dir, file_name, conn)
            elif input_type == "object":
                handle_object(temp_dir, file_name, conn)
            else:
                conn.sendall(b"ERROR: Invalid input type. Expected 'source' or 'object'\n")

    except Exception as e:
        print(f"DEBUG: Exception in handle_client: {e}")
        conn.sendall(f"ERROR: {str(e)}\n".encode())
    finally:
        print("DEBUG: Closing client connection")
        conn.close()

def start_server():
    print("DEBUG: Starting daemon server")
    source_and_load_env(PATH_TO_SHELL_SCRIPT)

    if os.path.exists(SOCKET_PATH):
        os.remove(SOCKET_PATH)

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server_sock:
        server_sock.bind(SOCKET_PATH)
        os.chmod(SOCKET_PATH, 0o700)
        server_sock.listen()

        print(f"Daemon listening on {SOCKET_PATH}...")
        while True:
            print("DEBUG: Waiting for client connections...")
            conn, _ = server_sock.accept()
            threading.Thread(target=handle_client, args=(conn,), daemon=True).start()

if __name__ == "__main__":
    try:
        start_server()
    except KeyboardInterrupt:
        print("DEBUG: Shutting down daemon")
        if os.path.exists(SOCKET_PATH):
            os.remove(SOCKET_PATH)
