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

"""Configuration management for Keeper Slack Integration."""

import os
import yaml
from typing import Dict, Any, Optional
from dataclasses import dataclass

from .logger import logger


@dataclass
class SlackConfig:
    """Slack application configuration."""
    
    app_token: str
    """App-level token for Socket Mode (xapp-1-...)"""
    
    bot_token: str
    """Bot user OAuth token (xoxb-...)"""
    
    signing_secret: str
    """Signing secret for verifying requests from Slack"""
    
    approvals_channel_id: str
    """Channel ID where approval requests are posted"""


@dataclass
class KeeperConfig:
    """Keeper Service Mode configuration."""
    
    service_url: str
    """URL of Keeper Commander Service Mode server"""
    
    api_key: Optional[str] = None
    """API key for authenticating with Service Mode (if required)"""


@dataclass
class PEDMConfig:
    """PEDM (Privileged Elevation & Delegation Management) polling configuration."""
    
    enabled: bool = False
    """Whether PEDM polling is enabled"""
    
    polling_interval: int = 120
    """Polling interval in seconds (default: 120 = 2 minutes)"""


@dataclass
class DeviceApprovalConfig:
    """Device Approval polling configuration."""
    
    enabled: bool = False
    """Whether Device Approval polling is enabled"""
    
    polling_interval: int = 120
    """Polling interval in seconds (default: 120 = 2 minutes)"""


class Config:
    """
    Application configuration manager.
    
    Loads configuration from YAML file and environment variables.
    Environment variables take precedence over file configuration.
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize configuration.
        """
        self._data = {}
        
        # Try to load from file
        if config_path and os.path.exists(config_path):
            self._load_from_file(config_path)
        else:
            # Try default locations
            self._try_default_locations()
        
        # Override with environment variables
        self._load_from_env()
        
        # Validate required fields
        self._validate()
    
    def _load_from_file(self, config_path: str):
        """Load configuration from YAML file."""
        try:
            with open(config_path, 'r') as f:
                file_config = yaml.safe_load(f)
                if file_config:
                    self._data.update(file_config)
        except Exception as e:
            logger.warning(f"Could not load config file {config_path}: {e}")
    
    def _try_default_locations(self):
        """Try to load configuration from default locations."""
        default_paths = [
            os.path.expanduser("~/.keeper/slack_config.yaml"),
            "./slack_config.yaml",
            "./config/slack_config.yaml"
        ]
        
        for path in default_paths:
            if os.path.exists(path):
                self._load_from_file(path)
                break
    
    def _load_from_env(self):
        """Load and override configuration from environment variables."""
        env_mappings = {
            'SLACK_APP_TOKEN': ('slack', 'app_token'),
            'SLACK_BOT_TOKEN': ('slack', 'bot_token'),
            'SLACK_SIGNING_SECRET': ('slack', 'signing_secret'),
            'APPROVALS_CHANNEL_ID': ('slack', 'approvals_channel_id'),
            'KEEPER_SERVICE_URL': ('keeper', 'service_url'),
            'KEEPER_API_KEY': ('keeper', 'api_key'),
            'PEDM_ENABLED': ('pedm', 'enabled'),
            'PEDM_POLLING_INTERVAL': ('pedm', 'polling_interval'),
            'DEVICE_APPROVAL_ENABLED': ('device_approval', 'enabled'),
            'DEVICE_APPROVAL_POLLING_INTERVAL': ('device_approval', 'polling_interval'),
        }
        
        for env_var, (section, key) in env_mappings.items():
            value = os.environ.get(env_var)
            if value:
                if section not in self._data:
                    self._data[section] = {}
                # Convert boolean and integer values
                if key == 'enabled':
                    value = value.lower() in ('true', '1', 'yes')
                elif key == 'polling_interval':
                    value = int(value)
                self._data[section][key] = value
    
    def _validate(self):
        """Validate required configuration fields."""
        # Note: keeper.service_url is optional here - can be configured via App Home
        # and loaded from ~/.keeper/slack_dynamic_settings.yaml
        required_fields = [
            ('slack', 'app_token', 'SLACK_APP_TOKEN'),
            ('slack', 'bot_token', 'SLACK_BOT_TOKEN'),
            ('slack', 'signing_secret', 'SLACK_SIGNING_SECRET'),
            ('slack', 'approvals_channel_id', 'APPROVALS_CHANNEL_ID'),
        ]
        
        missing = []
        for section, key, env_var in required_fields:
            if section not in self._data or key not in self._data[section]:
                missing.append(env_var)
        
        if missing:
            raise ValueError(
                f"Missing required configuration: {', '.join(missing)}\n\n"
                f"Set these via environment variables or in slack_config.yaml\n"
                f"See SLACK_SETUP.md for detailed instructions."
            )
    
    @property
    def slack(self) -> SlackConfig:
        """Get Slack configuration."""
        slack_data = self._data['slack']
        return SlackConfig(
            app_token=slack_data['app_token'],
            bot_token=slack_data['bot_token'],
            signing_secret=slack_data['signing_secret'],
            approvals_channel_id=slack_data['approvals_channel_id']
        )
    
    @property
    def keeper(self) -> KeeperConfig:
        """
        Get Keeper configuration.

        """
        # Dynamic settings via App Home UI (DISABLED)
        # Uncomment below to re-enable UI settings
        # try:
        #     from .settings_store import get_settings_store
        #     settings_store = get_settings_store()
        #     dynamic_settings = settings_store.load()
        #     
        #     if dynamic_settings and dynamic_settings.service_url:
        #         logger.info(f"Using dynamic Keeper settings: {dynamic_settings.service_url}")
        #         return KeeperConfig(
        #             service_url=dynamic_settings.service_url,
        #             api_key=dynamic_settings.api_key
        #         )
        # except Exception as e:
        #     logger.debug(f"Could not load dynamic settings: {e}")
        
        # Load config from YAML file or environment variables
        keeper_data = self._data.get('keeper', {})
        if keeper_data.get('service_url'):
            return KeeperConfig(
                service_url=keeper_data.get('service_url'),
                api_key=keeper_data.get('api_key')
            )
        
        # Default fallback - configure via config file or App Home
        logger.info("No Keeper config found. Configure via slack_config.yaml or environment variables.")
        return KeeperConfig(
            service_url='http://localhost:8080',
            api_key=None
        )
    
    @property
    def pedm(self) -> PEDMConfig:
        """
        Get PEDM polling configuration.
        """
        pedm_data = self._data.get('pedm', {})
        return PEDMConfig(
            enabled=pedm_data.get('enabled', False),
            polling_interval=pedm_data.get('polling_interval', 120)
        )
    
    @property
    def device_approval(self) -> DeviceApprovalConfig:
        """
        Get Device Approval polling configuration.
        """
        device_data = self._data.get('device_approval', {})
        return DeviceApprovalConfig(
            enabled=device_data.get('enabled', False),
            polling_interval=device_data.get('polling_interval', 120)
        )
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by key."""
        return self._data.get(key, default)
    
    def update_keeper_config(self, service_url: str, api_key: Optional[str] = None):
        """
        Update Keeper configuration dynamically.
        This saves the settings to the dynamic settings store,
        which takes priority over static configuration.
        """
        from .settings_store import get_settings_store
        settings_store = get_settings_store()
        settings_store.save(service_url=service_url, api_key=api_key)
