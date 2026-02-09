"""
Configuration management for KrakenGuard daemon

Loads and validates configuration from daemon.yaml.
"""

import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional


class Config:
    """Configuration manager for KrakenGuard daemon."""
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize configuration.
        
        Args:
            config_path: Path to daemon.yaml. If None, searches in standard locations.
        """
        if config_path is None:
            # Try standard locations
            possible_paths = [
                "/opt/krakenguard/daemon/daemon.yaml",
                os.path.join(os.path.dirname(__file__), "daemon.yaml"),
                "daemon.yaml"
            ]
            config_path = None
            for path in possible_paths:
                if os.path.exists(path):
                    config_path = path
                    break
            
            if config_path is None:
                raise FileNotFoundError("Could not find daemon.yaml in standard locations")
        
        self.config_path = config_path
        self._config: Dict[str, Any] = {}
        self.load()
        self.validate()
    
    def load(self) -> None:
        """Load configuration from YAML file."""
        with open(self.config_path, 'r') as f:
            self._config = yaml.safe_load(f) or {}
    
    def validate(self) -> None:
        """Validate configuration and check that required paths exist."""
        # Validate daemon section
        if 'daemon' not in self._config:
            raise ValueError("Missing 'daemon' section in configuration")
        
        # Validate paths section
        if 'paths' not in self._config:
            raise ValueError("Missing 'paths' section in configuration")
        
        # Validate storage section
        if 'storage' not in self._config:
            raise ValueError("Missing 'storage' section in configuration")
        
        # Validate KLEE section
        if 'klee' not in self._config:
            raise ValueError("Missing 'klee' section in configuration")
        
        # Check that critical paths exist (if they're absolute paths)
        paths = self._config.get('paths', {})
        for key, path in paths.items():
            if path and os.path.isabs(path) and not os.path.exists(path):
                # Warn but don't fail - paths might be set up later
                print(f"Warning: Path '{key}' ({path}) does not exist")
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value using dot notation.
        
        Args:
            key: Configuration key (e.g., 'daemon.socket_path')
            default: Default value if key not found
            
        Returns:
            Configuration value
        """
        keys = key.split('.')
        value = self._config
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
                if value is None:
                    return default
            else:
                return default
        return value
    
    @property
    def socket_path(self) -> str:
        """Get socket path."""
        return self.get('daemon.socket_path', '/var/run/krakenguard.sock')
    
    @property
    def socket_permissions(self) -> int:
        """Get socket permissions as integer."""
        perms = self.get('daemon.socket_permissions', '0770')
        # Handle both string (e.g., "0770") and integer (YAML may parse 0770 as int)
        if isinstance(perms, int):
            # If it's already an integer, it's likely already in decimal form
            # But if it was parsed from octal YAML (0770), it's already correct
            return perms
        elif isinstance(perms, str):
            # Convert string octal to integer
            return int(perms, 8)
        else:
            # Fallback to default
            return int('0770', 8)
    
    @property
    def log_level(self) -> str:
        """Get log level."""
        return self.get('daemon.log_level', 'INFO')
    
    @property
    def log_file(self) -> str:
        """Get log file path."""
        return self.get('daemon.log_file', '/data/logs/krakenguard.log')
    
    @property
    def paths(self) -> Dict[str, str]:
        """Get all paths."""
        return self.get('paths', {})
    
    @property
    def data_dir(self) -> str:
        """Get data directory."""
        return self.get('storage.data_dir', '/data')
    
    @property
    def requests_dir(self) -> str:
        """Get requests directory."""
        return self.get('storage.requests_dir', '/data/requests')
    
    @property
    def klee_config(self) -> Dict[str, Any]:
        """Get KLEE configuration."""
        return self.get('klee', {})


# Global config instance (lazy initialization)
_config_instance: Optional[Config] = None


def get_config(config_path: Optional[str] = None) -> Config:
    """
    Get global configuration instance.
    
    Args:
        config_path: Path to config file (only used on first call)
        
    Returns:
        Config instance
    """
    global _config_instance
    if _config_instance is None:
        _config_instance = Config(config_path)
    return _config_instance
