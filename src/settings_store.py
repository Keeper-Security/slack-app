# -*- coding: utf-8 -*-
#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2022 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

"""
Settings store for dynamic Keeper configuration.

This module provides persistent storage for Keeper Service Mode settings
that can be updated via the Slack App Home tab without server access.
"""

import os
import yaml
import json
from datetime import datetime
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict
from pathlib import Path
import threading


@dataclass
class KeeperSettings:
    """Dynamic Keeper Service Mode settings."""
    service_url: str
    api_key: Optional[str] = None
    last_updated: Optional[str] = None
    updated_by: Optional[str] = None
    updated_by_name: Optional[str] = None


class SettingsStore:
    """
    Persistent settings store using YAML file.
    Settings are stored in ~/.keeper/slack_dynamic_settings.yaml
    and can be updated via the Slack App Home tab.
    """
    
    DEFAULT_SETTINGS_PATH = os.path.expanduser("~/.keeper/slack_dynamic_settings.yaml")
    
    def __init__(self, settings_path: Optional[str] = None):
        """
        Initialize settings store.
        """
        self._settings_path = settings_path or self.DEFAULT_SETTINGS_PATH
        self._lock = threading.Lock()
        self._cache: Optional[KeeperSettings] = None
        
        # Ensure directory exists
        settings_dir = os.path.dirname(self._settings_path)
        if settings_dir:
            os.makedirs(settings_dir, exist_ok=True)
    
    @property
    def settings_path(self) -> str:
        """Get the settings file path."""
        return self._settings_path
    
    def load(self) -> Optional[KeeperSettings]:
        """
        Load settings from YAML file.
        """
        with self._lock:
            if not os.path.exists(self._settings_path):
                return None
            
            try:
                with open(self._settings_path, 'r') as f:
                    data = yaml.safe_load(f)
                
                if not data or 'keeper' not in data:
                    return None
                
                keeper_data = data['keeper']
                self._cache = KeeperSettings(
                    service_url=keeper_data.get('service_url', ''),
                    api_key=keeper_data.get('api_key'),
                    last_updated=keeper_data.get('last_updated'),
                    updated_by=keeper_data.get('updated_by'),
                    updated_by_name=keeper_data.get('updated_by_name')
                )
                return self._cache
                
            except Exception as e:
                print(f"[WARN] Could not load dynamic settings: {e}")
                return None
    
    def save(
        self, 
        service_url: str, 
        api_key: Optional[str] = None,
        updated_by: Optional[str] = None,
        updated_by_name: Optional[str] = None
    ) -> KeeperSettings:
        """
        Save settings to YAML file.
        """
        with self._lock:
            settings = KeeperSettings(
                service_url=service_url.strip().rstrip('/') + '/',  # Normalize URL
                api_key=api_key.strip() if api_key else None,
                last_updated=datetime.utcnow().isoformat() + 'Z',
                updated_by=updated_by,
                updated_by_name=updated_by_name
            )
            
            data = {
                'keeper': {
                    'service_url': settings.service_url,
                    'api_key': settings.api_key,
                    'last_updated': settings.last_updated,
                    'updated_by': settings.updated_by,
                    'updated_by_name': settings.updated_by_name
                }
            }
            
            try:
                with open(self._settings_path, 'w') as f:
                    yaml.dump(data, f, default_flow_style=False, sort_keys=False)
                
                self._cache = settings
                print(f"[OK] Settings saved to {self._settings_path}")
                return settings
                
            except Exception as e:
                print(f"[ERROR] Failed to save settings: {e}")
                raise
    
    def get_cached(self) -> Optional[KeeperSettings]:
        """Get cached settings without reading from disk."""
        return self._cache
    
    def clear(self):
        """Clear the settings file."""
        with self._lock:
            if os.path.exists(self._settings_path):
                os.remove(self._settings_path)
            self._cache = None
            print(f"[OK] Settings cleared")
    
    def exists(self) -> bool:
        """Check if settings file exists."""
        return os.path.exists(self._settings_path)


# Global settings store instance
_settings_store: Optional[SettingsStore] = None


def get_settings_store(settings_path: Optional[str] = None) -> SettingsStore:
    """
    Get the global settings store instance.
    """
    global _settings_store
    if _settings_store is None:
        _settings_store = SettingsStore(settings_path)
    return _settings_store

