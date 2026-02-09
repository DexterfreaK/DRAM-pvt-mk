"""
Protocol module for KrakenGuard daemon communication

Defines request/response message formats and serialization.
"""

import json
import base64
from dataclasses import dataclass, field, asdict
from typing import Dict, Optional, Any, List


@dataclass
class LoadOptions:
    """Options for loading eBPF program."""
    attach_type: str  # xdp, kprobe, tracepoint, etc.
    attach_target: str  # interface name, function name, etc.
    pin_path: Optional[str] = None  # Optional pin path in /sys/fs/bpf


@dataclass
class FileInfo:
    """Information about a file in the request."""
    name: str
    size: int
    encoding: str  # "base64" or "utf8"
    data: Optional[bytes] = None  # Actual file data (not serialized in JSON)


@dataclass
class Request:
    """Request message from client."""
    version: str = "1.0"
    request_id: str = ""
    action: str = "load"  # "load" or "verify" or "health"
    retain_results: bool = True
    files: Dict[str, FileInfo] = field(default_factory=dict)
    options: Dict[str, Any] = field(default_factory=dict)
    load_options: Optional[LoadOptions] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result = {
            "version": self.version,
            "request_id": self.request_id,
            "action": self.action,
            "retain_results": self.retain_results,
            "files": {},
            "options": self.options
        }
        
        # Serialize files (without data, just metadata)
        for key, file_info in self.files.items():
            result["files"][key] = {
                "name": file_info.name,
                "size": file_info.size,
                "encoding": file_info.encoding
            }
        
        # Serialize load_options if present
        if self.load_options:
            result["load_options"] = asdict(self.load_options)
        
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Request':
        """Create Request from dictionary."""
        files = {}
        for key, file_data in data.get("files", {}).items():
            files[key] = FileInfo(
                name=file_data["name"],
                size=file_data["size"],
                encoding=file_data["encoding"]
            )
        
        load_options = None
        if "load_options" in data and data["load_options"]:
            load_options = LoadOptions(**data["load_options"])
        
        return cls(
            version=data.get("version", "1.0"),
            request_id=data.get("request_id", ""),
            action=data.get("action", "load"),
            retain_results=data.get("retain_results", True),
            files=files,
            options=data.get("options", {}),
            load_options=load_options
        )


@dataclass
class HelperFunctionResult:
    """Result of helper function verification."""
    valid: bool
    message: str
    restricted_helpers: List[str] = field(default_factory=list)


@dataclass
class MapAccessResult:
    """Result of map access verification."""
    valid: bool
    message: str
    violations: List[str] = field(default_factory=list)


@dataclass
class VerificationResult:
    """Result of eBPF program verification."""
    passed: bool
    helper_functions: HelperFunctionResult = field(default_factory=lambda: HelperFunctionResult(valid=False, message=""))
    map_access: MapAccessResult = field(default_factory=lambda: MapAccessResult(valid=False, message=""))


@dataclass
class LoadResult:
    """Result of eBPF program loading."""
    loaded: bool
    program_fd: int = -1
    attach_status: str = ""
    attach_target: Optional[str] = None
    pin_path: Optional[str] = None
    message: str = ""
    error: Optional[str] = None


@dataclass
class ExecutionInfo:
    """Execution information."""
    duration_seconds: float = 0.0
    paths_explored: int = 0
    total_instructions: int = 0
    return_code: int = 0


@dataclass
class OutputInfo:
    """Output information."""
    stdout: str = ""
    stderr: str = ""
    directory: str = ""
    files: Dict[str, str] = field(default_factory=dict)


@dataclass
class ErrorInfo:
    """Error information."""
    stage: str = ""
    code: str = ""
    message: str = ""
    details: str = ""


@dataclass
class Response:
    """Response message to client."""
    version: str = "1.0"
    request_id: str = ""
    status: str = "success"  # "success", "verification_failed", "error"
    verification_result: Optional[VerificationResult] = None
    load_result: Optional[LoadResult] = None
    execution: Optional[ExecutionInfo] = None
    output: Optional[OutputInfo] = None
    error: Optional[ErrorInfo] = None
    retained: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result = {
            "version": self.version,
            "request_id": self.request_id,
            "status": self.status,
            "retained": self.retained
        }
        
        if self.verification_result:
            result["verification_result"] = {
                "passed": self.verification_result.passed,
                "helper_functions": asdict(self.verification_result.helper_functions),
                "map_access": asdict(self.verification_result.map_access)
            }
        
        if self.load_result:
            result["load_result"] = asdict(self.load_result)
        
        if self.execution:
            result["execution"] = asdict(self.execution)
        
        if self.output:
            result["output"] = {
                "stdout": self.output.stdout,
                "stderr": self.output.stderr,
                "directory": self.output.directory,
                "files": self.output.files
            }
        
        if self.error:
            result["error"] = asdict(self.error)
        
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Response':
        """Create Response from dictionary."""
        verification_result = None
        if "verification_result" in data:
            vf_data = data["verification_result"]
            verification_result = VerificationResult(
                passed=vf_data.get("passed", False),
                helper_functions=HelperFunctionResult(**vf_data.get("helper_functions", {})),
                map_access=MapAccessResult(**vf_data.get("map_access", {}))
            )
        
        load_result = None
        if "load_result" in data:
            load_result = LoadResult(**data["load_result"])
        
        execution = None
        if "execution" in data:
            execution = ExecutionInfo(**data["execution"])
        
        output = None
        if "output" in data:
            output_data = data["output"]
            output = OutputInfo(
                stdout=output_data.get("stdout", ""),
                stderr=output_data.get("stderr", ""),
                directory=output_data.get("directory", ""),
                files=output_data.get("files", {})
            )
        
        error = None
        if "error" in data:
            error = ErrorInfo(**data["error"])
        
        return cls(
            version=data.get("version", "1.0"),
            request_id=data.get("request_id", ""),
            status=data.get("status", "success"),
            verification_result=verification_result,
            load_result=load_result,
            execution=execution,
            output=output,
            error=error,
            retained=data.get("retained", False)
        )


# Serialization functions

def serialize_message(obj: Any) -> bytes:
    """
    Serialize a message object to length-prefixed JSON.
    
    Args:
        obj: Request or Response object
        
    Returns:
        Length-prefixed JSON bytes
    """
    if isinstance(obj, Request):
        json_data = json.dumps(obj.to_dict())
    elif isinstance(obj, Response):
        json_data = json.dumps(obj.to_dict())
    else:
        json_data = json.dumps(obj)
    
    json_bytes = json_data.encode('utf-8')
    length = len(json_bytes)
    
    # Prepend 4-byte length (big-endian)
    length_bytes = length.to_bytes(4, byteorder='big')
    return length_bytes + json_bytes


def deserialize_message(data: bytes) -> Dict[str, Any]:
    """
    Deserialize length-prefixed JSON message.
    
    Args:
        data: Length-prefixed JSON bytes
        
    Returns:
        Parsed dictionary
    """
    if len(data) < 4:
        raise ValueError("Message too short: missing length prefix")
    
    length = int.from_bytes(data[:4], byteorder='big')
    if len(data) < 4 + length:
        raise ValueError(f"Message incomplete: expected {4 + length} bytes, got {len(data)}")
    
    json_data = data[4:4+length].decode('utf-8')
    return json.loads(json_data)


def encode_file(data: bytes, encoding: str = "base64") -> str:
    """
    Encode file data for transmission.
    
    Args:
        data: File data as bytes
        encoding: Encoding type ("base64" or "utf8")
        
    Returns:
        Encoded string
    """
    if encoding == "base64":
        return base64.b64encode(data).decode('ascii')
    elif encoding == "utf8":
        return data.decode('utf-8')
    else:
        raise ValueError(f"Unsupported encoding: {encoding}")


def decode_file(encoded_data: str, encoding: str = "base64") -> bytes:
    """
    Decode file data from transmission.
    
    Args:
        encoded_data: Encoded file data
        encoding: Encoding type ("base64" or "utf8")
        
    Returns:
        Decoded bytes
    """
    if encoding == "base64":
        return base64.b64decode(encoded_data)
    elif encoding == "utf8":
        return encoded_data.encode('utf-8')
    else:
        raise ValueError(f"Unsupported encoding: {encoding}")


def read_message(sock) -> Dict[str, Any]:
    """
    Read a length-prefixed message from socket.
    
    Args:
        sock: Socket object
        
    Returns:
        Parsed message dictionary
    """
    # Read length prefix (4 bytes)
    length_data = b''
    while len(length_data) < 4:
        chunk = sock.recv(4 - len(length_data))
        if not chunk:
            raise ConnectionError("Connection closed while reading message length")
        length_data += chunk
    
    length = int.from_bytes(length_data, byteorder='big')
    
    # Read message body
    message_data = b''
    while len(message_data) < length:
        chunk = sock.recv(min(4096, length - len(message_data)))
        if not chunk:
            raise ConnectionError("Connection closed while reading message body")
        message_data += chunk
    
    return deserialize_message(length_data + message_data)


def write_message(sock, obj: Any) -> None:
    """
    Write a length-prefixed message to socket.
    
    Args:
        sock: Socket object
        obj: Request or Response object to send
    """
    message_bytes = serialize_message(obj)
    sock.sendall(message_bytes)
