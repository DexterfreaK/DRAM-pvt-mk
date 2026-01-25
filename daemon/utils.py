"""
Utility functions for KrakenGuard daemon

File management, logging, and helper functions.
"""

import os
import shutil
import logging
from pathlib import Path
from typing import Optional


def create_request_directory(request_id: str, base_dir: str) -> dict:
    """
    Create directory structure for a request.
    
    Args:
        request_id: Unique request identifier
        base_dir: Base directory for requests
        
    Returns:
        Dictionary with paths: input_dir, intermediate_dir, output_dir
    """
    request_dir = os.path.join(base_dir, request_id)
    input_dir = os.path.join(request_dir, "input")
    intermediate_dir = os.path.join(request_dir, "intermediate")
    output_dir = os.path.join(request_dir, "output")
    
    os.makedirs(input_dir, exist_ok=True)
    os.makedirs(intermediate_dir, exist_ok=True)
    os.makedirs(output_dir, exist_ok=True)
    
    return {
        "request_dir": request_dir,
        "input_dir": input_dir,
        "intermediate_dir": intermediate_dir,
        "output_dir": output_dir
    }


def cleanup_request_directory(request_dir: str) -> None:
    """
    Remove request directory and all contents.
    
    Args:
        request_dir: Path to request directory
    """
    if os.path.exists(request_dir):
        shutil.rmtree(request_dir)


def save_uploaded_file(file_data: bytes, file_path: str) -> None:
    """
    Save uploaded file data to disk.
    
    Args:
        file_data: File data as bytes
        file_path: Destination file path
    """
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, 'wb') as f:
        f.write(file_data)


def ensure_directory_exists(path: str) -> None:
    """
    Ensure directory exists, create if it doesn't.
    
    Args:
        path: Directory path
    """
    os.makedirs(path, exist_ok=True)


def setup_logging(log_file: Optional[str] = None, log_level: str = "INFO") -> None:
    """
    Configure structured logging for the daemon.
    
    Args:
        log_file: Path to log file (if None, logs to stdout)
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    """
    level = getattr(logging, log_level.upper(), logging.INFO)
    
    # Format: [timestamp] [level] [request_id] [component] message
    log_format = '[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s'
    date_format = '%Y-%m-%dT%H:%M:%SZ'
    
    handlers = []
    
    if log_file:
        # Ensure log directory exists
        log_dir = os.path.dirname(log_file)
        if log_dir:
            ensure_directory_exists(log_dir)
        handlers.append(logging.FileHandler(log_file))
    else:
        handlers.append(logging.StreamHandler())
    
    logging.basicConfig(
        level=level,
        format=log_format,
        datefmt=date_format,
        handlers=handlers
    )


def get_logger(name: str) -> logging.Logger:
    """
    Get logger for a component.
    
    Args:
        name: Component name (e.g., 'socket', 'handler', 'pipeline')
        
    Returns:
        Logger instance
    """
    return logging.getLogger(name)
