#!/usr/bin/env python3
"""
Test client for KrakenGuard daemon

Example usage of the daemon client library.
"""

import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from daemon.draco_client import KrakenGuardClient


def find_socket_path():
    """
    Find the socket path by checking common locations.
    
    Returns:
        str: Path to socket file, or None if not found
    """
    # Get project root (parent of daemon directory)
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    # Check locations in order of preference
    possible_paths = [
        os.path.join(project_root, "socket", "krakenguard.sock"),  # docker-compose mount
        "/var/run/krakenguard.sock",  # default system location
        "./socket/krakenguard.sock",  # relative to current directory
    ]
    
    for path in possible_paths:
        if os.path.exists(path):
            return path
    
    return None


def test_health():
    """Test health check."""
    print("Testing health check...")
    socket_path = find_socket_path()
    if not socket_path:
        print("Error: Socket not found. Checked locations:")
        print("  - ./socket/krakenguard.sock (docker-compose mount)")
        print("  - /var/run/krakenguard.sock (default)")
        print("\nMake sure the container is running: sudo docker-compose up -d")
        return
    
    client = KrakenGuardClient(socket_path=socket_path)
    try:
        response = client.health()
        print(f"Health check: {response.status}")
        print(f"Response: {response.to_dict()}")
    except Exception as e:
        print(f"Health check failed: {e}")


def test_verify(object_file: str, constraints_file: str, config_file: str = None, debug: bool = False):
    """Test verification (dry-run)."""
    print(f"\nTesting verification...")
    print(f"Object file: {object_file}")
    print(f"Constraints: {constraints_file}")
    if config_file:
        print(f"Config: {config_file}")
    if debug:
        print("Debug mode: ENABLED (stdout/stderr will be saved to execution.log)")
    
    socket_path = find_socket_path()
    if not socket_path:
        print("Error: Socket not found. Make sure the container is running: sudo docker-compose up -d")
        return
    
    client = KrakenGuardClient(socket_path=socket_path)
    try:
        response = client.verify(
            object_file=object_file,
            constraints_file=constraints_file,
            config_file=config_file,
            timeout=300,
            debug=debug
        )
        
        print(f"\nVerification Status: {response.status}")
        if response.verification_result:
            print(f"Passed: {response.verification_result.passed}")
            print(f"Helper Functions: {response.verification_result.helper_functions.message}")
            print(f"Map Access: {response.verification_result.map_access.message}")
        
        if response.execution:
            print(f"\nExecution Statistics:")
            print(f"Paths Explored: {response.execution.paths_explored}")
            print(f"Total Instructions: {response.execution.total_instructions}")
            print(f"Duration: {response.execution.duration_seconds:.2f}s")
        
        if response.output:
            print(f"\nOutput Directory: {response.output.directory}")
            print(f"Output Files: {list(response.output.files.keys())}")
            if debug and "execution.log" in response.output.files:
                print(f"Debug log: {response.output.files['execution.log']}")
        
        if response.error:
            print(f"\nError: {response.error.message}")
            
    except Exception as e:
        print(f"Verification failed: {e}")
        import traceback
        traceback.print_exc()


def test_load(object_file: str, constraints_file: str, config_file: str = None, debug: bool = False):
    """Test load (verify + load)."""
    print(f"\nTesting load...")
    print(f"Object file: {object_file}")
    print(f"Constraints: {constraints_file}")
    if config_file:
        print(f"Config: {config_file}")
    if debug:
        print("Debug mode: ENABLED (stdout/stderr will be saved to execution.log)")
    
    socket_path = find_socket_path()
    if not socket_path:
        print("Error: Socket not found. Make sure the container is running: sudo docker-compose up -d")
        return
    
    client = KrakenGuardClient(socket_path=socket_path)
    try:
        response = client.load(
            object_file=object_file,
            constraints_file=constraints_file,
            config_file=config_file,
            attach_type="xdp",
            attach_target="eth0",
            timeout=300,
            debug=debug
        )
        
        print(f"\nStatus: {response.status}")
        if response.verification_result:
            print(f"Verification Passed: {response.verification_result.passed}")
        
        if response.execution:
            print(f"\nExecution Statistics:")
            print(f"Paths Explored: {response.execution.paths_explored}")
            print(f"Total Instructions: {response.execution.total_instructions}")
            print(f"Duration: {response.execution.duration_seconds:.2f}s")
        
        if response.load_result:
            print(f"\nLoad Result:")
            print(f"Loaded: {response.load_result.loaded}")
            print(f"Program FD: {response.load_result.program_fd}")
            print(f"Message: {response.load_result.message}")
        
        if response.output and debug and "execution.log" in response.output.files:
            print(f"\nDebug log: {response.output.files['execution.log']}")
        
        if response.error:
            print(f"\nError: {response.error.message}")
            
    except Exception as e:
        print(f"Load failed: {e}")
        import traceback
        traceback.print_exc()


def test_cross_program(
    object1_file: str,
    object2_file: str,
    constraints_file: str,
    program_config_file: str,
    prog1_func: str,
    prog2_func: str,
    debug: bool = False
):
    """Test cross-program verification (two eBPF programs)."""
    print("\nTesting cross-program verification...")
    print(f"Program 1: {object1_file} -> {prog1_func}")
    print(f"Program 2: {object2_file} -> {prog2_func}")
    print(f"Constraints: {constraints_file}")
    print(f"Config: {program_config_file}")
    if debug:
        print("Debug mode: ENABLED")
    
    socket_path = find_socket_path()
    if not socket_path:
        print("Error: Socket not found. Make sure the container is running: sudo docker-compose up -d")
        return
    
    client = KrakenGuardClient(socket_path=socket_path)
    try:
        response = client.verify_cross_program(
            object1_file=object1_file,
            object2_file=object2_file,
            constraints_file=constraints_file,
            program_config_file=program_config_file,
            prog1_func=prog1_func,
            prog2_func=prog2_func,
            timeout=300,
            debug=debug
        )
        print(f"\nVerification Status: {response.status}")
        if response.verification_result:
            print(f"Passed: {response.verification_result.passed}")
            print(f"Helper Functions: {response.verification_result.helper_functions.message}")
            print(f"Map Access: {response.verification_result.map_access.message}")
        if response.execution:
            print(f"\nExecution Statistics:")
            print(f"Paths Explored: {response.execution.paths_explored}")
            print(f"Total Instructions: {response.execution.total_instructions}")
            print(f"Duration: {response.execution.duration_seconds:.2f}s")
        if response.output:
            print(f"\nOutput Directory: {response.output.directory}")
        if response.error:
            print(f"\nError: {response.error.message}")
    except Exception as e:
        print(f"Cross-program verification failed: {e}")
        import traceback
        traceback.print_exc()


def main():
    """Main test function."""
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python3 test_client.py health")
        print("  python3 test_client.py verify <object_file> <constraints_file> [config_file] [--debug]")
        print("  python3 test_client.py load <object_file> <constraints_file> [config_file] [--debug]")
        print("  python3 test_client.py cross-program <obj1> <obj2> <constraints> <program_config.yaml> <prog1_func> <prog2_func> [--debug]")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == "health":
        test_health()
    elif command == "cross-program":
        if len(sys.argv) < 8:
            print("Error: cross-program requires: object1 object2 constraints program_config.yaml prog1_func prog2_func")
            print("Example: python3 test_client.py cross-program ../katran/balancer_main.o ../electrode/fast_kern.o constraints.json program_config.yaml balancer_ingress fastPaxos_main")
            sys.exit(1)
        args = sys.argv[2:]
        debug = "--debug" in args
        if debug:
            args.remove("--debug")
        test_cross_program(
            object1_file=args[0],
            object2_file=args[1],
            constraints_file=args[2],
            program_config_file=args[3],
            prog1_func=args[4],
            prog2_func=args[5],
            debug=debug
        )
    elif command == "verify":
        if len(sys.argv) < 4:
            print("Error: verify requires object_file and constraints_file")
            sys.exit(1)
        # Parse arguments
        args = sys.argv[2:]
        debug = "--debug" in args
        if debug:
            args.remove("--debug")
        object_file = args[0]
        constraints_file = args[1]
        config_file = args[2] if len(args) > 2 else None
        test_verify(object_file, constraints_file, config_file, debug=debug)
    elif command == "load":
        if len(sys.argv) < 4:
            print("Error: load requires object_file and constraints_file")
            sys.exit(1)
        # Parse arguments
        args = sys.argv[2:]
        debug = "--debug" in args
        if debug:
            args.remove("--debug")
        object_file = args[0]
        constraints_file = args[1]
        config_file = args[2] if len(args) > 2 else None
        test_load(object_file, constraints_file, config_file, debug=debug)
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)


if __name__ == "__main__":
    main()
