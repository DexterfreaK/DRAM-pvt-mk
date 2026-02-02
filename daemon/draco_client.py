"""
KrakenGuard Client Library

Python client for communicating with the KrakenGuard daemon.
"""

import os
import socket
import uuid
from typing import Optional, Dict, Any
from .protocol import (
    Request, Response, FileInfo, LoadOptions,
    read_message, write_message, encode_file
)


class KrakenGuardClient:
    """Client for communicating with KrakenGuard daemon."""
    
    def __init__(self, socket_path: str = "/var/run/krakenguard.sock"):
        """
        Initialize client.
        
        Args:
            socket_path: Path to daemon Unix socket
        """
        self.socket_path = socket_path
        self.conn = None
    
    def connect(self):
        """Connect to daemon."""
        if not os.path.exists(self.socket_path):
            raise ConnectionError(f"Socket not found: {self.socket_path}")
        
        self.conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.conn.connect(self.socket_path)
    
    def disconnect(self):
        """Disconnect from daemon."""
        if self.conn:
            self.conn.close()
            self.conn = None
    
    def _send(self, obj: Any):
        """Send message to daemon."""
        if not self.conn:
            raise ConnectionError("Not connected to daemon")
        write_message(self.conn, obj)
    
    def _receive(self) -> Dict[str, Any]:
        """Receive message from daemon."""
        if not self.conn:
            raise ConnectionError("Not connected to daemon")
        return read_message(self.conn)
    
    def load(
        self,
        object_file: str,
        constraints_file: str,
        config_file: Optional[str] = None,
        attach_type: str = "xdp",
        attach_target: str = "",
        pin_path: Optional[str] = None,
        entry_function: Optional[str] = None,
        timeout: Optional[int] = None,
        retain_results: bool = True,
        debug: bool = False
    ) -> Response:
        """
        Load an eBPF program (verify + load).
        
        Args:
            object_file: Path to eBPF object file
            constraints_file: Path to constraints.json
            config_file: Path to program_config.yaml (optional)
            attach_type: Attachment type (xdp, kprobe, etc.)
            attach_target: Target (interface name, function name, etc.)
            pin_path: Optional pin path in /sys/fs/bpf
            entry_function: Entry function name (optional)
            timeout: Timeout in seconds (optional)
            retain_results: Whether to retain results
            
        Returns:
            Response object
        """
        if not self.conn:
            self.connect()
        
        try:
            # Read files
            with open(object_file, 'rb') as f:
                object_data = f.read()
            
            with open(constraints_file, 'r') as f:
                constraints_data = f.read()
            
            config_data = None
            if config_file and os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    config_data = f.read()
            
            # Encode files and calculate sizes
            object_encoded = encode_file(object_data, "base64")
            object_encoded_bytes = object_encoded.encode('ascii')
            constraints_encoded = constraints_data.encode('utf-8')
            
            # Build request
            request = Request(
                version="1.0",
                request_id=str(uuid.uuid4()),
                action="load",
                retain_results=retain_results,
                files={
                    "object": FileInfo(
                        name=os.path.basename(object_file),
                        size=len(object_encoded_bytes),
                        encoding="base64",
                        data=object_encoded_bytes
                    ),
                    "constraints": FileInfo(
                        name=os.path.basename(constraints_file),
                        size=len(constraints_encoded),
                        encoding="utf8",
                        data=constraints_encoded
                    )
                },
                options={
                    "entry_function": entry_function,
                    "timeout": timeout,
                    "debug": debug
                },
                load_options=LoadOptions(
                    attach_type=attach_type,
                    attach_target=attach_target,
                    pin_path=pin_path
                )
            )
            
            if config_data:
                config_encoded = config_data.encode('utf-8')
                request.files["config"] = FileInfo(
                    name=os.path.basename(config_file),
                    size=len(config_encoded),
                    encoding="utf8",
                    data=config_encoded
                )
            
            # Send request header
            self._send(request)
            
            # Send file data (already encoded)
            for file_info in request.files.values():
                self.conn.sendall(file_info.data)
            
            # Receive response
            response_dict = self._receive()
            return Response.from_dict(response_dict)
            
        finally:
            self.disconnect()
    
    def verify(
        self,
        object_file: str,
        constraints_file: str,
        config_file: Optional[str] = None,
        entry_function: Optional[str] = None,
        timeout: Optional[int] = None,
        retain_results: bool = True,
        debug: bool = False
    ) -> Response:
        """
        Verify an eBPF program (dry-run, no load).
        
        Args:
            object_file: Path to eBPF object file
            constraints_file: Path to constraints.json
            config_file: Path to program_config.yaml (optional)
            entry_function: Entry function name (optional)
            timeout: Timeout in seconds (optional)
            retain_results: Whether to retain results
            
        Returns:
            Response object
        """
        if not self.conn:
            self.connect()
        
        try:
            # Read files
            with open(object_file, 'rb') as f:
                object_data = f.read()
            
            with open(constraints_file, 'r') as f:
                constraints_data = f.read()
            
            config_data = None
            if config_file and os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    config_data = f.read()
            
            # Encode files and calculate sizes
            object_encoded = encode_file(object_data, "base64")
            object_encoded_bytes = object_encoded.encode('ascii')
            constraints_encoded = constraints_data.encode('utf-8')
            
            # Build request
            request = Request(
                version="1.0",
                request_id=str(uuid.uuid4()),
                action="verify",
                retain_results=retain_results,
                files={
                    "object": FileInfo(
                        name=os.path.basename(object_file),
                        size=len(object_encoded_bytes),
                        encoding="base64",
                        data=object_encoded_bytes
                    ),
                    "constraints": FileInfo(
                        name=os.path.basename(constraints_file),
                        size=len(constraints_encoded),
                        encoding="utf8",
                        data=constraints_encoded
                    )
                },
                options={
                    "entry_function": entry_function,
                    "timeout": timeout,
                    "debug": debug
                }
            )
            
            if config_data:
                config_encoded = config_data.encode('utf-8')
                request.files["config"] = FileInfo(
                    name=os.path.basename(config_file),
                    size=len(config_encoded),
                    encoding="utf8",
                    data=config_encoded
                )
            
            # Send request header
            self._send(request)
            
            # Send file data (already encoded)
            for file_info in request.files.values():
                self.conn.sendall(file_info.data)
            
            # Receive response
            response_dict = self._receive()
            return Response.from_dict(response_dict)
            
        finally:
            self.disconnect()
    
    def verify_cross_program(
        self,
        object1_file: str,
        object2_file: str,
        constraints_file: str,
        program_config_file: str,
        prog1_func: str,
        prog2_func: str,
        timeout: Optional[int] = None,
        retain_results: bool = True,
        debug: bool = False
    ) -> Response:
        """
        Run cross-program verification (two eBPF programs linked for analysis).

        Args:
            object1_file: Path to first eBPF object file (e.g. balancer_main.o)
            object2_file: Path to second eBPF object file (e.g. fast_kern.o)
            constraints_file: Path to constraints.json
            program_config_file: Path to program_config.yaml (cross-program config)
            prog1_func: Entry function for program 1 (e.g. balancer_ingress)
            prog2_func: Entry function for program 2 (e.g. fastPaxos_main)
            timeout: Timeout in seconds (optional)
            retain_results: Whether to retain results
            debug: Enable debug output

        Returns:
            Response object
        """
        if not self.conn:
            self.connect()

        try:
            with open(object1_file, "rb") as f:
                object1_data = f.read()
            with open(object2_file, "rb") as f:
                object2_data = f.read()
            with open(constraints_file, "r") as f:
                constraints_data = f.read()
            with open(program_config_file, "r") as f:
                config_data = f.read()

            object1_encoded = encode_file(object1_data, "base64")
            object1_encoded_bytes = object1_encoded.encode("ascii")
            object2_encoded = encode_file(object2_data, "base64")
            object2_encoded_bytes = object2_encoded.encode("ascii")
            constraints_encoded = constraints_data.encode("utf-8")
            config_encoded = config_data.encode("utf-8")

            request = Request(
                version="1.0",
                request_id=str(uuid.uuid4()),
                action="cross_program",
                retain_results=retain_results,
                files={
                    "object1": FileInfo(
                        name=os.path.basename(object1_file),
                        size=len(object1_encoded_bytes),
                        encoding="base64",
                        data=object1_encoded_bytes
                    ),
                    "object2": FileInfo(
                        name=os.path.basename(object2_file),
                        size=len(object2_encoded_bytes),
                        encoding="base64",
                        data=object2_encoded_bytes
                    ),
                    "constraints": FileInfo(
                        name=os.path.basename(constraints_file),
                        size=len(constraints_encoded),
                        encoding="utf8",
                        data=constraints_encoded
                    ),
                    "config": FileInfo(
                        name=os.path.basename(program_config_file),
                        size=len(config_encoded),
                        encoding="utf8",
                        data=config_encoded
                    )
                },
                options={
                    "prog1_func": prog1_func,
                    "prog2_func": prog2_func,
                    "timeout": timeout,
                    "debug": debug
                }
            )

            self._send(request)
            for file_info in request.files.values():
                self.conn.sendall(file_info.data)
            response_dict = self._receive()
            return Response.from_dict(response_dict)
        finally:
            self.disconnect()

    def health(self) -> Response:
        """
        Check daemon health.
        
        Returns:
            Response object
        """
        if not self.conn:
            self.connect()
        
        try:
            request = Request(
                version="1.0",
                request_id=str(uuid.uuid4()),
                action="health"
            )
            
            self._send(request)
            response_dict = self._receive()
            return Response.from_dict(response_dict)
            
        finally:
            self.disconnect()
