#!/usr/bin/env python3
import socket
import sys
import os

SOCKET_PATH = "/tmp/ebpf_verifier.sock"

def send_verification_request(folder_path, file_name, input_type):
    if not os.path.exists(SOCKET_PATH):
        print(f"ERROR: Socket {SOCKET_PATH} not found. Is the daemon running?")
        sys.exit(1)

    if not os.path.exists(folder_path):
        print(f"ERROR: Folder '{folder_path}' does not exist.")
        sys.exit(1)

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.connect(SOCKET_PATH)

        message = f"{folder_path}\n{file_name}\n{input_type}\n"
        client.sendall(message.encode())

        response = b""
        while True:
            chunk = client.recv(4096)
            if not chunk:
                break
            response += chunk

        print(response.decode(errors='replace'))

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python3 client_test.py <ebpf_folder_path> <file_name> <source|object>")
        sys.exit(1)

    folder_path = sys.argv[1]
    file_name = sys.argv[2]
    input_type = sys.argv[3].strip().lower()
    if input_type not in ["source", "object"]:
        print("ERROR: Input type must be either 'source' or 'object'")
        sys.exit(1)

    send_verification_request(folder_path, file_name, input_type)

