# config.py
import yaml
import os
from typing import Dict, Optional

_CONFIG: Optional[Dict] = None

def load_config(config_path: str = "config.yaml") -> Dict:
    """Load configuration once and cache it."""
    global _CONFIG
    if _CONFIG is None:
        with open(config_path, 'r') as f:
            _CONFIG = yaml.safe_load(f)
    return _CONFIG

def get_config() -> Dict:
    """Return cached configuration."""
    if _CONFIG is None:
        raise RuntimeError("Configuration not loaded. Call load_config() first.")
    return _CONFIG