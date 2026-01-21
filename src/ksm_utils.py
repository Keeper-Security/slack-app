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
KSM (Keeper Secrets Manager) utility functions for fetching credentials.
"""

import os
import json
import base64
import tempfile
from typing import Dict, Any, Optional

from .logger import logger


def check_ksm_dependency() -> bool:
    """Check if keeper_secrets_manager_core is installed.
    """
    try:
        import keeper_secrets_manager_core  # type: ignore[import-untyped]  # noqa: F401
        return True
    except ImportError:
        logger.warning("keeper_secrets_manager_core is not installed")
        return False


def is_base64_config(input_str: str) -> bool:
    """Detect if input is base64-encoded JSON.
    """
    if not input_str:
        return False
    
    # If it looks like a file path (starts with path indicators or exists as file)
    if (input_str.startswith('/') or input_str.startswith('./') or 
        input_str.startswith('../') or input_str.startswith('~') or 
        os.path.isfile(input_str)):
        return False

    try:
        decoded_bytes = base64.b64decode(input_str, validate=True)
        decoded_str = decoded_bytes.decode('utf-8')
        json.loads(decoded_str)  # Validate JSON
        return True
    except Exception:
        return False


def process_ksm_config(ksm_config_input: str) -> Optional[str]:
    """
    Process KSM config input - decode base64 or return file path.
    """
    if not ksm_config_input:
        return None
    
    if is_base64_config(ksm_config_input):
        # Create temporary directory
        try:
            if os.path.exists("/home/commander"):
                ksm_dir = tempfile.mkdtemp(prefix="ksm_", dir="/home/commander")
            else:
                ksm_dir = tempfile.mkdtemp(prefix="ksm_")
            
            config_path = os.path.join(ksm_dir, "ksm-config.json")
            
            # Decode and save config
            decoded_bytes = base64.b64decode(ksm_config_input)
            decoded_str = decoded_bytes.decode('utf-8')
            config_data = json.loads(decoded_str)
            
            # Basic validation of config structure
            if not isinstance(config_data, dict):
                logger.error("Invalid config format - must be JSON object")
                return None
            
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config_data, f, indent=2, ensure_ascii=False)
            
            # Set secure permissions
            os.chmod(config_path, 0o600)
            return config_path
        except Exception as e:
            logger.error(f"Failed to process KSM config: {e}")
            return None
    else:
        if os.path.isfile(ksm_config_input):
            return ksm_config_input
        else:
            logger.error("KSM config file not found")
            return None


def _initialize_secrets_manager(ksm_config_path: Optional[str] = None, 
                                ksm_token: Optional[str] = None):
    """
    Initialize SecretsManager.
    """
    if not check_ksm_dependency():
        return None
    
    try:
        from keeper_secrets_manager_core import SecretsManager  # type: ignore[import-untyped]
        from keeper_secrets_manager_core.storage import FileKeyValueStorage  # type: ignore[import-untyped]
        
        if ksm_config_path:
            if not os.path.exists(ksm_config_path):
                logger.error("KSM config file not found")
                return None
            return SecretsManager(config=FileKeyValueStorage(ksm_config_path))
        elif ksm_token:
            return SecretsManager(token=ksm_token)
        else:
            logger.error("Either ksm_config_path or ksm_token must be provided")
            return None
    except Exception as e:
        logger.error(f"Failed to initialize SecretsManager: {e}")
        return None


def get_secret_by_uid_or_title(secrets_manager, record_identifier: str):
    """
    Get secret by UID first, then by title as fallback.
    """
    # First try to get by UID
    try:
        secrets = secrets_manager.get_secrets([record_identifier])
        if secrets and len(secrets) > 0:
            logger.info(f"Found record by UID: {record_identifier}")
            return secrets[0]
        else:
            logger.debug(f"Record not found by UID: {record_identifier}, trying title lookup...")
    except Exception as e:
        # UID lookup failed, continue to title lookup
        logger.debug(f"UID lookup failed for {record_identifier}: {e}, trying title lookup...")
    
    # Try to get by title as fallback
    try:
        secrets = secrets_manager.get_secrets_by_title(record_identifier)
        
        if not secrets or len(secrets) == 0:
            logger.error(f"Record not found by UID or title: {record_identifier}")
            return None
        elif len(secrets) > 1:
            logger.error(f"Multiple records found with title '{record_identifier}' "
                        f"({len(secrets)} records). Please use UID or a unique title.")
            return None
        else:
            logger.info(f"Found record by title: {record_identifier}")
            return secrets[0]
            
    except Exception as e:
        logger.error(f"Failed to lookup record by title '{record_identifier}': {e}")
        return None


def _list_record_fields(secret) -> None:
    """
    Debug function to list all available fields in a KSM record.
    """
    try:
        logger.debug("=== Listing all fields in KSM record ===")
        # Try to get all fields
        if hasattr(secret, 'fields'):
            logger.debug(f"Record has 'fields' attribute: {type(secret.fields)}")
            for i, field in enumerate(secret.fields):
                logger.debug(f"Field {i}: {field}")
        # Try to get field names
        if hasattr(secret, 'field_names'):
            logger.debug(f"Field names: {secret.field_names}")
        # Try to get custom field names
        if hasattr(secret, 'custom_field_names'):
            logger.debug(f"Custom field names: {secret.custom_field_names}")
        # Try to get all attributes
        logger.debug(f"Record attributes: {dir(secret)}")
        logger.debug("=== End field listing ===")
    except Exception as e:
        logger.debug(f"Error listing fields: {e}")


def _extract_field_value(secret, field_label_pattern: str, field_type: Optional[str] = None) -> Optional[str]:
    """
    Extract field value from secret by label pattern.
    """
    def _get_field_value(field_obj):
        """Extract value from field object (handles both direct values and field objects)."""
        if field_obj is None:
            return None
        
        # If it's a list or tuple, get the first element and recurse
        if isinstance(field_obj, (list, tuple)):
            if len(field_obj) > 0:
                # Recursively process the first element
                return _get_field_value(field_obj[0])
            else:
                return None
        
        # If it's already a string or primitive, return it as string
        if isinstance(field_obj, (str, int, float, bool)):
            return str(field_obj)
        
        # If it has a value attribute, use that
        if hasattr(field_obj, 'value'):
            val = field_obj.value
            # Recursively process the value (handles nested lists)
            return _get_field_value(val)
        
        # If it has a get_default_value method, use that
        if hasattr(field_obj, 'get_default_value'):
            try:
                val = field_obj.get_default_value(str)
                # Recursively process the value (handles lists)
                return _get_field_value(val)
            except Exception:
                pass
        
        # Otherwise, try to convert to string
        try:
            result = str(field_obj) if field_obj else None
            # If the string representation looks like a list (starts with '['), 
            # it means we didn't extract properly - return None to try other methods
            if result and result.startswith('[') and result.endswith(']'):
                return None
            return result
        except Exception:
            return None
    
    try:
        # Try standard field first
        try:
            field_obj = secret.field(field_label_pattern)
            value = _get_field_value(field_obj)
            # Ensure we return a string, not a list
            if value:
                if isinstance(value, (list, tuple)):
                    value = value[0] if len(value) > 0 else None
                return str(value).strip() if value else None
        except (AttributeError, KeyError, ValueError, TypeError):
            pass
        
        # Try custom field
        try:
            field_obj = secret.custom_field(field_label_pattern)
            value = _get_field_value(field_obj)
            # Ensure we return a string, not a list
            if value:
                if isinstance(value, (list, tuple)):
                    value = value[0] if len(value) > 0 else None
                return str(value).strip() if value else None
        except (AttributeError, KeyError, ValueError, TypeError):
            pass
        
        # Try with variations (underscore, hyphen)
        variations = [
            field_label_pattern.replace('_', '-'),
            field_label_pattern.replace('-', '_'),
            field_label_pattern.lower(),
            field_label_pattern.upper(),
        ]
        
        for variation in variations:
            if variation == field_label_pattern:
                continue
            try:
                field_obj = secret.field(variation)
                value = _get_field_value(field_obj)
                # Ensure we return a string, not a list
                if value:
                    if isinstance(value, (list, tuple)):
                        value = value[0] if len(value) > 0 else None
                    if value:
                        return str(value).strip()
            except (AttributeError, KeyError, ValueError, TypeError):
                pass
            
            try:
                field_obj = secret.custom_field(variation)
                value = _get_field_value(field_obj)
                # Ensure we return a string, not a list
                if value:
                    if isinstance(value, (list, tuple)):
                        value = value[0] if len(value) > 0 else None
                    if value:
                        return str(value).strip()
            except (AttributeError, KeyError, ValueError, TypeError):
                pass
        
        return None
    except Exception as e:
        logger.debug(f"Error extracting field value '{field_label_pattern}': {e}")
        return None


def fetch_credentials_from_ksm(
    ksm_config: Optional[str] = None,
    commander_record_title: Optional[str] = None,
    slack_record_title: Optional[str] = None
) -> Dict[str, Any]:
    """
    Fetch credentials from KSM records by title.
    """
    config_data = {}
    
    if not check_ksm_dependency():
        logger.warning("KSM not available, skipping KSM credential fetch")
        return config_data
    
    # Process KSM config
    ksm_config_path = None
    if ksm_config:
        ksm_config_path = process_ksm_config(ksm_config)
        if not ksm_config_path:
            logger.error("Failed to process KSM config")
            return config_data
    
    # Initialize SecretsManager
    secrets_manager = _initialize_secrets_manager(ksm_config_path=ksm_config_path)
    if not secrets_manager:
        logger.error("Failed to initialize SecretsManager")
        return config_data
    
    # Fetch Keeper Service Mode credentials from "CSMD config"
    if commander_record_title:
        try:
            secret = get_secret_by_uid_or_title(secrets_manager, commander_record_title)
            if secret:
                keeper_config = {}
                
                # Extract service_url and api_key fields
                service_url = _extract_field_value(secret, 'service_url') or _extract_field_value(secret, 'service-url')
                api_key = _extract_field_value(secret, 'api_key') or _extract_field_value(secret, 'api-key')
                
                # Check notes for JSON config
                try:
                    notes_value = _extract_field_value(secret, 'notes')
                    if notes_value:
                        try:
                            notes_json = json.loads(notes_value)
                            if 'service_url' in notes_json:
                                service_url = notes_json['service_url']
                            if 'api_key' in notes_json:
                                api_key = notes_json['api_key']
                        except (json.JSONDecodeError, TypeError):
                            pass
                except Exception:
                    # Notes field not found or not accessible
                    pass
                
                if service_url:
                    keeper_config['service_url'] = service_url
                if api_key:
                    keeper_config['api_key'] = api_key
                
                if keeper_config:
                    config_data['keeper'] = keeper_config
                else:
                    logger.warning("No Keeper config extracted from KSM record")
        except Exception as e:
            logger.error(f"Failed to fetch commander record: {e}")
            import traceback
            logger.debug(traceback.format_exc())
    
    # Fetch Slack credentials from "CSMD slack config"
    if slack_record_title:
        try:
            secret = get_secret_by_uid_or_title(secrets_manager, slack_record_title)
            if secret:
                slack_config = {}
                pedm_config = {}
                device_approval_config = {}
                
                # Extract Slack fields with exact names
                app_token = _extract_field_value(secret, 'slack_app_token')
                bot_token = _extract_field_value(secret, 'slack_bot_token')
                signing_secret = _extract_field_value(secret, 'slack_signing_secret')
                channel_id = _extract_field_value(secret, 'approvals_channel_id')
                
                # Extract PEDM config
                pedm_enabled = _extract_field_value(secret, 'pedm_enabled')
                pedm_interval = _extract_field_value(secret, 'pedm_polling_interval')
                
                # Extract Device Approval config
                device_enabled = _extract_field_value(secret, 'device_approval_enabled')
                device_interval = _extract_field_value(secret, 'device_approval_polling_interval')
                
                # Check notes for JSON config (overrides field values)
                try:
                    notes_value = _extract_field_value(secret, 'notes')
                    if notes_value:
                        try:
                            notes_json = json.loads(notes_value)
                            # Slack credentials
                            if 'slack_app_token' in notes_json:
                                app_token = notes_json['slack_app_token']
                            if 'slack_bot_token' in notes_json:
                                bot_token = notes_json['slack_bot_token']
                            if 'slack_signing_secret' in notes_json:
                                signing_secret = notes_json['slack_signing_secret']
                            if 'approvals_channel_id' in notes_json:
                                channel_id = notes_json['approvals_channel_id']
                            # PEDM config
                            if 'pedm_enabled' in notes_json:
                                pedm_enabled = notes_json['pedm_enabled']
                            if 'pedm_polling_interval' in notes_json:
                                pedm_interval = notes_json['pedm_polling_interval']
                            # Device Approval config
                            if 'device_approval_enabled' in notes_json:
                                device_enabled = notes_json['device_approval_enabled']
                            if 'device_approval_polling_interval' in notes_json:
                                device_interval = notes_json['device_approval_polling_interval']
                        except (json.JSONDecodeError, TypeError):
                            pass
                except Exception:
                    pass


                def _clean_value(value):
                    """Clean and extract value from list or string."""
                    if value is None:
                        return None
                    # If it's a list, get first element
                    if isinstance(value, (list, tuple)):
                        if len(value) > 0:
                            value = value[0]
                        else:
                            return None
                    # Convert to string and strip
                    return str(value).strip() if value else None
                
                app_token_clean = _clean_value(app_token)
                if app_token_clean:
                    slack_config['app_token'] = app_token_clean
                else:
                    logger.warning("app_token not found or empty in KSM record")
                
                bot_token_clean = _clean_value(bot_token)
                if bot_token_clean:
                    slack_config['bot_token'] = bot_token_clean
                else:
                    logger.warning("bot_token not found or empty in KSM record")
                
                signing_secret_clean = _clean_value(signing_secret)
                if signing_secret_clean:
                    slack_config['signing_secret'] = signing_secret_clean
                else:
                    logger.warning("signing_secret not found or empty in KSM record")
                
                channel_id_clean = _clean_value(channel_id)
                if channel_id_clean:
                    slack_config['approvals_channel_id'] = channel_id_clean
                else:
                    logger.warning("approvals_channel_id not found or empty in KSM record")
                
                # Set PEDM values
                if pedm_enabled is not None:
                    if isinstance(pedm_enabled, str):
                        pedm_config['enabled'] = pedm_enabled.lower() in ('true', '1', 'yes')
                    else:
                        pedm_config['enabled'] = bool(pedm_enabled)
                if pedm_interval:
                    try:
                        pedm_config['polling_interval_in_sec'] = int(pedm_interval)
                    except (ValueError, TypeError):
                        pedm_config['polling_interval_in_sec'] = 120  # Default
                
                # Set Device Approval values
                if device_enabled is not None:
                    if isinstance(device_enabled, str):
                        device_approval_config['enabled'] = device_enabled.lower() in ('true', '1', 'yes')
                    else:
                        device_approval_config['enabled'] = bool(device_enabled)
                if device_interval:
                    try:
                        device_approval_config['polling_interval_in_sec'] = int(device_interval)
                    except (ValueError, TypeError):
                        device_approval_config['polling_interval_in_sec'] = 120  # Default
                
                if slack_config:
                    config_data['slack'] = slack_config
                    required_slack_fields = ['app_token', 'bot_token', 'signing_secret', 'approvals_channel_id']
                    missing_fields = [f for f in required_slack_fields if f not in slack_config]
                    if missing_fields:
                        logger.warning(f"Missing Slack fields in KSM record: {missing_fields}")
                else:
                    logger.warning("No Slack config extracted from KSM record")
                if pedm_config:
                    config_data['pedm'] = pedm_config
                if device_approval_config:
                    config_data['device_approval'] = device_approval_config
        except Exception as e:
            logger.error(f"Failed to fetch slack record: {e}")
            import traceback
            logger.debug(traceback.format_exc())
    
    # Summary message for successful credential fetch
    fetched_items = []
    if 'keeper' in config_data:
        fetched_items.append("Service Mode Credentials")
    if 'slack' in config_data:
        fetched_items.append("Slack Credentials")

    if fetched_items:
        logger.info(f"Credentials fetched successfully from KSM vault: {', '.join(fetched_items)}")
    
    return config_data
