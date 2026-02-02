"""
KrakenGuard Daemon - Main server process

Handles Unix socket communication, request processing, and orchestration
of the verification pipeline and BPF loading.
"""

import os
import socket
import threading
import signal
import sys
import uuid
import time
from .config import get_config
from .utils import setup_logging, get_logger, create_request_directory, save_uploaded_file
from .protocol import (
    Request, Response, read_message, write_message, decode_file, FileInfo,
    VerificationResult, HelperFunctionResult, MapAccessResult, LoadResult,
    ExecutionInfo, OutputInfo, ErrorInfo
)
from .pipeline import (
    run_lifting_pipeline, run_cross_program_pipeline, run_klee_verification,
    parse_verification_results, is_verification_passed, collect_output_files,
    parse_klee_statistics
)
from .loader import BPFLoader

logger = get_logger("daemon")


class KrakenGuardDaemon:
    """Main daemon server class."""
    
    def __init__(self, config_path: str = None):
        """Initialize daemon."""
        self.config = get_config(config_path)
        self.socket_path = self.config.socket_path
        self.server_socket = None
        self.running = False
        self.processing_lock = threading.Lock()  # Ensures sequential processing
        self.loader = BPFLoader()
        
        # Setup logging
        setup_logging(
            log_file=self.config.log_file,
            log_level=self.config.log_level
        )
        
        logger.info("KrakenGuard daemon initialized")
    
    def start(self):
        """Start the daemon server."""
        # Remove existing socket if it exists
        if os.path.exists(self.socket_path):
            os.remove(self.socket_path)
        
        # Create Unix socket
        self.server_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server_socket.bind(self.socket_path)
        
        # Set socket permissions
        os.chmod(self.socket_path, self.config.socket_permissions)
        
        # Listen for connections
        self.server_socket.listen(5)
        
        self.running = True
        logger.info(f"Daemon listening on {self.socket_path}")
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        # Main accept loop
        try:
            while self.running:
                try:
                    conn, addr = self.server_socket.accept()
                    logger.info("Client connected")
                    
                    # Process request sequentially
                    with self.processing_lock:
                        self._handle_client(conn)
                        
                except socket.error as e:
                    if self.running:
                        logger.error(f"Socket error: {e}")
        except KeyboardInterrupt:
            logger.info("Received interrupt signal")
        finally:
            self.stop()
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        logger.info(f"Received signal {signum}, shutting down...")
        self.running = False
        if self.server_socket:
            self.server_socket.close()
    
    def _handle_client(self, conn):
        """Handle client connection."""
        request_id = None
        request_dirs = None
        try:
            # Receive request
            request = self._receive_request(conn)
            request_id = request.request_id
            logger.info(f"[{request_id}] Received {request.action} request")
            
            # Create request directory
            request_dirs = create_request_directory(
                request_id,
                self.config.requests_dir
            )
            
            # Save uploaded files
            self._save_request_files(request, request_dirs["input_dir"])
            
            # Process request
            response = self._handle_request(request, request_dirs)
            
            # Send response
            write_message(conn, response)
            logger.info(f"[{request_id}] Response sent")
            
        except Exception as e:
            logger.error(f"[{request_id}] Error handling client: {e}", exc_info=True)
            # Send error response
            try:
                error_response = Response(
                    version="1.0",
                    request_id=request_id or "",
                    status="error",
                    error=ErrorInfo(
                        stage="receive",
                        code="RECEIVE_ERROR",
                        message=str(e),
                        details=""
                    )
                )
                write_message(conn, error_response)
            except:
                pass
        finally:
            conn.close()
    
    def _receive_request(self, conn) -> Request:
        """
        Receive and parse request from client.
        
        Args:
            conn: Socket connection
            
        Returns:
            Request object
        """
        # Read message header
        message_dict = read_message(conn)
        request = Request.from_dict(message_dict)
        
        # Read file data
        for key, file_info in request.files.items():
            # Read file data from socket
            file_data = b''
            remaining = file_info.size
            while remaining > 0:
                chunk = conn.recv(min(4096, remaining))
                if not chunk:
                    raise ConnectionError(f"Connection closed while reading file {key}")
                file_data += chunk
                remaining -= len(chunk)
            
            # Decode file data
            if file_info.encoding == "base64":
                # Base64 data comes as ASCII string, decode to bytes first
                encoded_str = file_data.decode('ascii')
                decoded_data = decode_file(encoded_str, "base64")
            else:
                # UTF-8 data is already bytes
                decoded_data = file_data
            file_info.data = decoded_data
        
        return request
    
    def _save_request_files(self, request: Request, input_dir: str):
        """
        Save uploaded files to disk.
        
        Args:
            request: Request object with file data
            input_dir: Directory to save files
        """
        for key, file_info in request.files.items():
            if file_info.data:
                file_path = os.path.join(input_dir, file_info.name)
                save_uploaded_file(file_info.data, file_path)
                logger.debug(f"Saved {key} to {file_path}")
    
    def _handle_cross_program_request(
        self, request: Request, request_dirs: dict, start_time: float
    ) -> Response:
        """Handle cross-program verification request."""
        request_id = request.request_id
        for key in ("object1", "object2", "constraints", "config"):
            if key not in request.files:
                return Response(
                    version="1.0",
                    request_id=request_id,
                    status="error",
                    error=ErrorInfo(
                        stage="receive",
                        code="INVALID_REQUEST",
                        message=f"Cross-program request requires files: object1, object2, constraints, config. Missing: {key}",
                        details=""
                    ),
                    retained=request.retain_results
                )
        object1_file = os.path.join(request_dirs["input_dir"], request.files["object1"].name)
        object2_file = os.path.join(request_dirs["input_dir"], request.files["object2"].name)
        constraints_file = os.path.join(request_dirs["input_dir"], request.files["constraints"].name)
        program_config = os.path.join(request_dirs["input_dir"], request.files["config"].name)
        prog1_func = request.options.get("prog1_func") or request.options.get("entry_function")
        prog2_func = request.options.get("prog2_func")
        if not prog1_func or not prog2_func:
            return Response(
                version="1.0",
                request_id=request_id,
                status="error",
                error=ErrorInfo(
                    stage="receive",
                    code="INVALID_REQUEST",
                    message="Cross-program request requires options: prog1_func and prog2_func (or entry_func for prog1 and prog2_func for prog2)",
                    details=""
                ),
                retained=request.retain_results
            )
        debug = request.options.get("debug", False)
        debug_output_file = None
        if debug:
            debug_output_file = os.path.join(request_dirs["output_dir"], "execution.log")
            try:
                with open(debug_output_file, "w") as f:
                    f.write(f"Execution log for request: {request_id}\n")
                    f.write(f"Started at: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write("=" * 80 + "\n\n")
            except Exception as e:
                logger.warning(f"[{request_id}] Failed to create debug output file: {e}")
        try:
            logger.info(f"[{request_id}] Stage 1/3: Running cross-program lifting pipeline")
            final_ir_path, lift_stdout, lift_stderr = run_cross_program_pipeline(
                object1_file=object1_file,
                object2_file=object2_file,
                program_config=program_config,
                prog1_func=prog1_func,
                prog2_func=prog2_func,
                intermediate_dir=request_dirs["intermediate_dir"],
                debug=debug,
                debug_output_file=debug_output_file
            )
            logger.info(f"[{request_id}] Stage 2/3: Running KLEE verification")
            klee_output_dir, klee_stdout, klee_stderr, klee_return_code = run_klee_verification(
                final_ir_path=final_ir_path,
                constraints_file=constraints_file,
                output_dir=request_dirs["output_dir"],
                timeout=request.options.get("timeout"),
                debug=debug,
                debug_output_file=debug_output_file
            )
            logger.info(f"[{request_id}] Stage 3/3: Parsing verification results")
            verification_results = parse_verification_results(klee_output_dir)
            passed = is_verification_passed(verification_results)
            klee_stats = parse_klee_statistics(klee_output_dir)
            verification_result = VerificationResult(
                passed=passed,
                helper_functions=HelperFunctionResult(**verification_results["helper_functions"]),
                map_access=MapAccessResult(**verification_results["map_access"])
            )
            output_files = collect_output_files(klee_output_dir)
            if debug and debug_output_file and os.path.exists(debug_output_file):
                output_files["execution.log"] = debug_output_file
            duration = time.time() - start_time
            return Response(
                version="1.0",
                request_id=request_id,
                status="success" if passed else "verification_failed",
                verification_result=verification_result,
                load_result=LoadResult(
                    loaded=False,
                    message="Cross-program analysis does not support load"
                ),
                execution=ExecutionInfo(
                    duration_seconds=duration,
                    paths_explored=klee_stats["paths_explored"],
                    total_instructions=klee_stats["total_instructions"],
                    return_code=klee_return_code
                ),
                output=OutputInfo(
                    stdout=lift_stdout + "\n" + klee_stdout,
                    stderr=lift_stderr + "\n" + klee_stderr,
                    directory=klee_output_dir,
                    files=output_files
                ),
                retained=request.retain_results
            )
        except Exception as e:
            logger.error(f"[{request_id}] Error in cross-program request: {e}", exc_info=True)
            if debug and debug_output_file:
                try:
                    with open(debug_output_file, "a") as f:
                        f.write("=" * 80 + "\nERROR\n" + "=" * 80 + "\n")
                        f.write(f"Error: {str(e)}\n")
                        import traceback
                        traceback.print_exc(file=f)
                except Exception:
                    pass
            return Response(
                version="1.0",
                request_id=request_id,
                status="error",
                error=ErrorInfo(
                    stage="processing",
                    code="PROCESSING_ERROR",
                    message=str(e),
                    details=""
                ),
                load_result=LoadResult(loaded=False, message="Pipeline error"),
                retained=request.retain_results
            )
    
    def _handle_request(self, request: Request, request_dirs: dict) -> Response:
        """
        Handle verification and loading request.
        
        Args:
            request: Request object
            request_dirs: Dictionary with request directory paths
            
        Returns:
            Response object
        """
        request_id = request.request_id
        start_time = time.time()
        
        # Handle health check
        if request.action == "health":
            return Response(
                version="1.0",
                request_id=request_id,
                status="success",
                execution=ExecutionInfo(duration_seconds=time.time() - start_time)
            )
        
        # Handle cross-program analysis
        if request.action == "cross_program":
            return self._handle_cross_program_request(request, request_dirs, start_time)
        
        # Single-program: get file paths
        object_file = os.path.join(request_dirs["input_dir"], request.files["object"].name)
        constraints_file = os.path.join(request_dirs["input_dir"], request.files["constraints"].name)
        program_config = None
        if "config" in request.files:
            program_config = os.path.join(request_dirs["input_dir"], request.files["config"].name)
        
        entry_function = request.options.get("entry_function")
        debug = request.options.get("debug", False)
        
        # Set up debug output file if debug mode is enabled
        debug_output_file = None
        if debug:
            debug_output_file = os.path.join(request_dirs["output_dir"], "execution.log")
            # Clear/create the file at the start
            try:
                with open(debug_output_file, 'w') as f:
                    f.write(f"Execution log for request: {request_id}\n")
                    f.write(f"Started at: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write("=" * 80 + "\n\n")
            except Exception as e:
                logger.warning(f"[{request_id}] Failed to create debug output file: {e}")
        
        try:
            # Step 1: Run lifting pipeline
            logger.info(f"[{request_id}] Stage 1/3: Running lifting pipeline")
            final_ir_path, lift_stdout, lift_stderr = run_lifting_pipeline(
                object_file=object_file,
                program_config=program_config,
                entry_function=entry_function,
                intermediate_dir=request_dirs["intermediate_dir"],
                debug=debug,
                debug_output_file=debug_output_file
            )
            
            # Step 2: Run KLEE verification
            logger.info(f"[{request_id}] Stage 2/3: Running KLEE verification")
            klee_output_dir, klee_stdout, klee_stderr, klee_return_code = run_klee_verification(
                final_ir_path=final_ir_path,
                constraints_file=constraints_file,
                output_dir=request_dirs["output_dir"],
                timeout=request.options.get("timeout"),
                debug=debug,
                debug_output_file=debug_output_file
            )
            
            # Step 3: Parse results
            logger.info(f"[{request_id}] Stage 3/3: Parsing verification results")
            verification_results = parse_verification_results(klee_output_dir)
            passed = is_verification_passed(verification_results)
            
            # Parse KLEE statistics
            klee_stats = parse_klee_statistics(klee_output_dir)
            
            # Build verification result
            verification_result = VerificationResult(
                passed=passed,
                helper_functions=HelperFunctionResult(**verification_results["helper_functions"]),
                map_access=MapAccessResult(**verification_results["map_access"])
            )
            
            # Step 4: Load program if verification passed and action is "load"
            load_result = None
            if passed and request.action == "load" and request.load_options:
                logger.info(f"[{request_id}] Verification passed, loading program")
                load_result_dict = self.loader.load_program(object_file, request.load_options)
                load_result = LoadResult(**load_result_dict)
            elif not passed:
                logger.warning(f"[{request_id}] Verification failed, not loading program")
                load_result = LoadResult(
                    loaded=False,
                    message="Verification failed - program not loaded"
                )
            
            # Collect output files
            output_files = collect_output_files(klee_output_dir)
            
            # Add debug output file if it exists
            if debug and debug_output_file and os.path.exists(debug_output_file):
                output_files["execution.log"] = debug_output_file
                logger.info(f"[{request_id}] Debug output saved to {debug_output_file}")
            
            # Build response
            duration = time.time() - start_time
            return Response(
                version="1.0",
                request_id=request_id,
                status="success" if passed else "verification_failed",
                verification_result=verification_result,
                load_result=load_result,
                execution=ExecutionInfo(
                    duration_seconds=duration,
                    paths_explored=klee_stats["paths_explored"],
                    total_instructions=klee_stats["total_instructions"],
                    return_code=klee_return_code
                ),
                output=OutputInfo(
                    stdout=lift_stdout + "\n" + klee_stdout,
                    stderr=lift_stderr + "\n" + klee_stderr,
                    directory=klee_output_dir,
                    files=output_files
                ),
                retained=request.retain_results
            )
            
        except Exception as e:
            logger.error(f"[{request_id}] Error processing request: {e}", exc_info=True)
            
            # Write error to debug file if enabled
            if debug and debug_output_file:
                try:
                    with open(debug_output_file, 'a') as f:
                        f.write("=" * 80 + "\n")
                        f.write("ERROR\n")
                        f.write("=" * 80 + "\n")
                        f.write(f"Error: {str(e)}\n")
                        import traceback
                        f.write("\nTraceback:\n")
                        traceback.print_exc(file=f)
                        f.write("\n")
                except Exception as debug_err:
                    logger.warning(f"[{request_id}] Failed to write error to debug file: {debug_err}")
            
            return Response(
                version="1.0",
                request_id=request_id,
                status="error",
                error=ErrorInfo(
                    stage="processing",
                    code="PROCESSING_ERROR",
                    message=str(e),
                    details=""
                ),
                load_result=LoadResult(
                    loaded=False,
                    message="Pipeline error - program not loaded"
                ),
                retained=request.retain_results
            )
    
    def stop(self):
        """Stop the daemon server."""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        if os.path.exists(self.socket_path):
            os.remove(self.socket_path)
        logger.info("Daemon stopped")


def main():
    """Main entry point."""
    daemon = KrakenGuardDaemon()
    daemon.start()


if __name__ == "__main__":
    main()
