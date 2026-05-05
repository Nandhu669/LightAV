"""
LightAV Versioned Configuration Module

Loads configuration from config.yaml with version checking and migration support.
"""
import yaml
import os
from pathlib import Path
from copy import deepcopy

# Current expected config version
CURRENT_VERSION = 1

# Project root directory
PROJECT_ROOT = Path(__file__).parent.parent
CONFIG_FILE = PROJECT_ROOT / "config.yaml"


def get_default_config():
    """Return default configuration for current version."""
    return {
        "config_version": CURRENT_VERSION,
        "scan_paths": {
            "watched_directories": [],
            "excluded_directories": [],
            "file_extensions": [".exe", ".dll", ".msi", ".bat", ".cmd", ".ps1"]
        },
        "resource_limits": {
            "max_cpu_percent": 50,
            "max_memory_mb": 512,
            "max_scan_threads": 4,
            "scan_throttle_ms": 100
        },
        "logging": {
            "level": "INFO",
            "log_file": "logs/lightav.log",
            "max_file_size_mb": 10,
            "backup_count": 5
        },
        "model": {
            "model_path": "",
            "confidence_threshold": 0.85
        },
        "hash_cache": {
            "enabled": True,
            "max_entries": 10000,
            "expiration_hours": 24
        }
    }


def migrate_config(config):
    """
    Migrate configuration from older versions to current version.
    
    Args:
        config: Configuration dictionary to migrate
        
    Returns:
        Migrated configuration dictionary
    """
    version = config.get("config_version", 0)
    migrated = deepcopy(config)
    
    # Migration from version 0 (no version field) to version 1
    if version < 1:
        migrated["config_version"] = 1
        # Add any missing fields from defaults
        defaults = get_default_config()
        for key, value in defaults.items():
            if key not in migrated:
                migrated[key] = value
            elif isinstance(value, dict):
                # Merge nested dicts
                for subkey, subvalue in value.items():
                    if subkey not in migrated[key]:
                        migrated[key][subkey] = subvalue
        version = 1
    
    # Future migrations go here:
    # if version < 2:
    #     # migrate from v1 to v2
    #     version = 2
    
    return migrated


def validate_config(config):
    """
    Validate configuration has required fields.
    
    Args:
        config: Configuration dictionary to validate
        
    Returns:
        tuple: (is_valid, list of errors)
    """
    errors = []
    required_sections = ["scan_paths", "resource_limits", "logging", "model", "hash_cache"]
    
    for section in required_sections:
        if section not in config:
            errors.append(f"Missing required section: {section}")
    
    # Validate resource limits
    if "resource_limits" in config:
        limits = config["resource_limits"]
        if limits.get("max_cpu_percent", 0) > 100:
            errors.append("max_cpu_percent cannot exceed 100")
        if limits.get("max_cpu_percent", 0) < 1:
            errors.append("max_cpu_percent must be at least 1")
    
    # Validate model threshold
    if "model" in config:
        threshold = config["model"].get("confidence_threshold", 0)
        if not (0.0 <= threshold <= 1.0):
            errors.append("confidence_threshold must be between 0.0 and 1.0")
    
    return len(errors) == 0, errors


def load_config(config_path=None):
    """
    Load configuration from file with version checking and migration.
    
    Args:
        config_path: Optional path to config file. Defaults to project config.yaml
        
    Returns:
        Configuration dictionary
        
    Raises:
        FileNotFoundError: If config file doesn't exist
        ValueError: If config is invalid
    """
    path = Path(config_path) if config_path else CONFIG_FILE
    
    if not path.exists():
        # Create default config if doesn't exist
        config = get_default_config()
        save_config(config, path)
        return config
    
    with open(path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f) or {}
    
    # Check version and migrate if needed
    version = config.get("config_version", 0)
    if version < CURRENT_VERSION:
        config = migrate_config(config)
        # Save migrated config
        save_config(config, path)
    
    # Validate
    is_valid, errors = validate_config(config)
    if not is_valid:
        raise ValueError(f"Invalid configuration: {'; '.join(errors)}")
    
    return config


def save_config(config, config_path=None):
    """
    Save configuration to file.
    
    Args:
        config: Configuration dictionary to save
        config_path: Optional path to config file
    """
    path = Path(config_path) if config_path else CONFIG_FILE
    
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)


def get_config_version(config_path=None):
    """Get the version of a configuration file without loading it fully."""
    path = Path(config_path) if config_path else CONFIG_FILE
    
    if not path.exists():
        return 0
    
    with open(path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f) or {}
    
    return config.get("config_version", 0)


# Load configuration on module import
CONFIG = load_config()
