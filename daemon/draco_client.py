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
