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
App Home tab for Keeper Slack Integration.

Provides a settings interface for configuring Keeper Service Mode
directly from Slack without requiring server access.
"""

from typing import Optional, Dict, Any, List
from datetime import datetime

from .settings_store import get_settings_store, KeeperSettings
from .logger import logger


def build_app_home_view(
    current_settings: Optional[KeeperSettings] = None,
    is_admin: bool = True,
    connection_status: Optional[str] = None,
    error_message: Optional[str] = None,
    success_message: Optional[str] = None
) -> Dict[str, Any]:
    """
    Build the App Home tab view.
    """
    blocks: List[Dict[str, Any]] = []
    
    # Header
    blocks.append({
        "type": "header",
        "text": {
            "type": "plain_text",
            "text": "Keeper Commander",
            "emoji": False
        }
    })
    
    blocks.append({
        "type": "context",
        "elements": [
            {
                "type": "mrkdwn",
                "text": "Secure credential access and sharing for your team"
            }
        ]
    })
    
    blocks.append({"type": "divider"})
    
    # Show success message if present
    if success_message:
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*{success_message}*"
            }
        })
        blocks.append({"type": "divider"})
    
    # Show error message if present
    if error_message:
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f" *Error:* {error_message}"
            }
        })
        blocks.append({"type": "divider"})
    
    if not is_admin:
        # Non-admin view
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*Settings are managed by workspace administrators.*\n\nContact your admin to configure Keeper Service Mode settings."
            }
        })
        
        # Show available commands
        blocks.append({"type": "divider"})
        blocks.append({
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "Available Commands",
                "emoji": False
            }
        })
        blocks.extend(_build_commands_section())
        
    else:
        # Admin settings section
        blocks.append({
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "Keeper Service Mode Settings",
                "emoji": False
            }
        })
        
        blocks.append({
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": "Configure the connection to your Keeper Commander Service Mode server"
                }
            ]
        })
        
        # Current values
        current_url = current_settings.service_url if current_settings else ""
        current_key = current_settings.api_key if current_settings else ""
        masked_key = _mask_api_key(current_key) if current_key else ""
        
        # Service URL input
        blocks.append({
            "type": "input",
            "block_id": "service_url_block",
            "element": {
                "type": "plain_text_input",
                "action_id": "service_url_input",
                "placeholder": {
                    "type": "plain_text",
                    "text": "https://your-server.com/api/v2/"
                },
                "initial_value": current_url
            },
            "label": {
                "type": "plain_text",
                "text": "Service URL",
                "emoji": True
            },
            "hint": {
                "type": "plain_text",
                "text": "The URL of your Keeper Commander Service Mode server"
            }
        })
        
        # API Key input
        blocks.append({
            "type": "input",
            "block_id": "api_key_block",
            "optional": True,
            "element": {
                "type": "plain_text_input",
                "action_id": "api_key_input",
                "placeholder": {
                    "type": "plain_text",
                    "text": "Enter API key (leave empty to keep current)"
                }
            },
            "label": {
                "type": "plain_text",
                "text": "API Key",
                "emoji": True
            },
            "hint": {
                "type": "plain_text",
                "text": f"Current: {masked_key or 'Not set'} — Leave empty to keep current value"
            }
        })
        
        # Connection status
        if connection_status:
            status_prefix = "[OK]" if connection_status == "success" else "[FAILED]"
            status_text = "Connected successfully!" if connection_status == "success" else "Connection failed"
            blocks.append({
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"{status_prefix} *Connection Status:* {status_text}"
                    }
                ]
            })
        
        # Action buttons
        blocks.append({
            "type": "actions",
            "block_id": "settings_actions",
            "elements": [
                {
                    "type": "button",
                    "text": {
                        "type": "plain_text",
                        "text": "Test Connection",
                        "emoji": False
                    },
                    "action_id": "test_keeper_connection",
                    "style": "primary"
                },
                {
                    "type": "button",
                    "text": {
                        "type": "plain_text",
                        "text": "Save Settings",
                        "emoji": False
                    },
                    "action_id": "save_keeper_settings",
                    "style": "primary"
                }
            ]
        })
        
        # Last updated info
        if current_settings and current_settings.last_updated:
            try:
                updated_dt = datetime.fromisoformat(current_settings.last_updated.replace('Z', '+00:00'))
                updated_str = updated_dt.strftime("%b %d, %Y at %I:%M %p UTC")
            except:
                updated_str = current_settings.last_updated
            
            updated_by = f" by <@{current_settings.updated_by}>" if current_settings.updated_by else ""
            
            blocks.append({
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"Last saved: {updated_str}{updated_by}"
                    }
                ]
            })
        
        blocks.append({"type": "divider"})
        
        # Available commands section
        blocks.append({
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "Available Commands",
                "emoji": False
            }
        })
        blocks.extend(_build_commands_section())
    
    return {
        "type": "home",
        "blocks": blocks
    }


def _build_commands_section() -> List[Dict[str, Any]]:
    """Build the commands help section."""
    return [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    "*`/keeper-request-record`*\n"
                    "Request access to a specific record by UID or search for records\n\n"
                    "*`/keeper-request-folder`*\n"
                    "Request access to a folder by UID or search for folders\n\n"
                    "*`/keeper-one-time-share`*\n"
                    "Request a one-time share link to a Keeper record"
                )
            }
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": "*Tip:* Use record/folder UIDs for direct access, or leave empty to search"
                }
            ]
        }
    ]


def _mask_api_key(api_key: str) -> str:
    """Mask API key for display, showing only first and last 4 characters."""
    if not api_key:
        return ""
    if len(api_key) <= 8:
        return "••••••••"
    return f"{api_key[:4]}••••••••{api_key[-4:]}"


class AppHomeHandler:
    """
    Handles App Home tab events and interactions.
    """
    
    def __init__(self, config, keeper_client):
        """
        Initialize handler.
        
        Args:
            config: Application config
            keeper_client: KeeperClient instance
        """
        self.config = config
        self.keeper_client = keeper_client
        self.settings_store = get_settings_store()
    
    def handle_app_home_opened(self, client, event: Dict[str, Any]):
        """
        Handle app_home_opened event - render the home tab.
        
        Args:
            client: Slack client
            event: Event payload
        """
        user_id = event.get("user")
        
        try:
            # Check if user is admin
            is_admin = self._check_if_admin(client, user_id)
            
            # Load current settings
            current_settings = self.settings_store.load()
            
            # If no dynamic settings, use config defaults
            if not current_settings:
                from .settings_store import KeeperSettings
                current_settings = KeeperSettings(
                    service_url=self.config.keeper.service_url,
                    api_key=self.config.keeper.api_key
                )
            
            # Build and publish home view (UI settings disabled - use config files)
            view = build_app_home_view(
                current_settings=current_settings,
                is_admin=False
            )
            
            client.views_publish(user_id=user_id, view=view)
            logger.ok(f"Published App Home for user {user_id}")
            
        except Exception as e:
            logger.error(f"Failed to publish App Home: {e}")
            import traceback
            traceback.print_exc()
    
    def handle_test_connection(self, ack, body: Dict[str, Any], client):
        """
        Handle test connection button click.
        """
        ack()
        user_id = body["user"]["id"]
        
        try:
            # Get values from the home view state
            view = body.get("view", {})
            state = view.get("state", {}).get("values", {})
            
            service_url = state.get("service_url_block", {}).get("service_url_input", {}).get("value", "")
            api_key = state.get("api_key_block", {}).get("api_key_input", {}).get("value", "")
            
            if not service_url:
                self._update_home_with_error(client, user_id, "Service URL is required")
                return
            
            # If no new API key entered, use existing one
            if not api_key:
                current_settings = self.settings_store.load()
                if current_settings:
                    api_key = current_settings.api_key
                else:
                    api_key = self.config.keeper.api_key
            
            # Test connection with API key
            connection_ok = self._test_connection(service_url, api_key)
            
            # Update home view with result
            current_settings = self.settings_store.load()
            if not current_settings:
                from .settings_store import KeeperSettings
                current_settings = KeeperSettings(
                    service_url=service_url,
                    api_key=api_key
                )
            
            if connection_ok:
                # Show success status
                view = build_app_home_view(
                    current_settings=current_settings,
                    is_admin=False,
                    connection_status="success"
                )
                client.views_publish(user_id=user_id, view=view)
            else:
                # Show prominent error message
                self._update_home_with_error(
                    client, user_id,
                    "Connection failed! Please check your Service URL and API Key."
                )
            
        except Exception as e:
            logger.error(f"Failed to test connection: {e}")
            self._update_home_with_error(client, user_id, str(e))
    
    def handle_save_settings(self, ack, body: Dict[str, Any], client):
        """
        Handle save settings button click.
        """
        ack()
        user_id = body["user"]["id"]
        
        try:
            # Get values from the home view state
            view = body.get("view", {})
            state = view.get("state", {}).get("values", {})
            
            service_url = state.get("service_url_block", {}).get("service_url_input", {}).get("value", "")
            new_api_key = state.get("api_key_block", {}).get("api_key_input", {}).get("value", "")
            
            if not service_url:
                self._update_home_with_error(client, user_id, "Service URL is required")
                return
            
            # If no new API key provided, keep the old one
            if not new_api_key:
                current_settings = self.settings_store.load()
                if current_settings:
                    new_api_key = current_settings.api_key
                else:
                    new_api_key = self.config.keeper.api_key
            
            # Validate connection before saving
            connection_ok = self._test_connection(service_url, new_api_key)
            if not connection_ok:
                self._update_home_with_error(
                    client, user_id,
                    "Cannot save: Connection failed. Please verify your Service URL and API Key."
                )
                return
            
            # Get user info for audit
            try:
                user_info = client.users_info(user=user_id)
                user_name = user_info["user"].get("real_name", user_info["user"].get("name", "Unknown"))
            except:
                user_name = "Unknown"
            
            # Save settings (only if connection validated)
            saved_settings = self.settings_store.save(
                service_url=service_url,
                api_key=new_api_key,
                updated_by=user_id,
                updated_by_name=user_name
            )
            
            # Update the keeper client with new settings
            self._update_keeper_client(service_url, new_api_key)
            
            # Update home view with success message
            view = build_app_home_view(
                current_settings=saved_settings,
                is_admin=False,
                success_message="Settings saved successfully!"
            )
            
            client.views_publish(user_id=user_id, view=view)
            logger.ok(f"Settings saved by {user_name} ({user_id})")
            
        except Exception as e:
            logger.error(f"Failed to save settings: {e}")
            import traceback
            traceback.print_exc()
            self._update_home_with_error(client, user_id, str(e))
    
    def _check_if_admin(self, client, user_id: str) -> bool:
        """
        Check if user is a workspace admin or owner.
        Only admins/owners can modify Keeper Service Mode settings.
        """
        try:
            user_info = client.users_info(user=user_id)
            user = user_info.get("user", {})
            is_admin = user.get("is_admin", False)
            is_owner = user.get("is_owner", False)
            
            if is_admin or is_owner:
                logger.ok(f"User {user_id} is admin/owner - settings access granted")
                return True
            else:
                logger.info(f"User {user_id} is not admin - settings access denied")
                return False
        except Exception as e:
            logger.warning(f"Could not check admin status for {user_id}: {e}")
            return False  # Deny by default if we can't verify
    
    def _test_connection(self, service_url: str, api_key: str = None) -> bool:
        """Test connection to Keeper Service Mode with API key validation."""
        import requests
        
        # Normalize URL
        base_url = service_url.strip().rstrip('/')
        if not base_url.endswith('/api/v2'):
            base_url = f"{base_url}/api/v2"
        
        # Build headers with API key
        headers = {'Content-Type': 'application/json'}
        if api_key:
            headers['api-key'] = api_key
        
        # Test queue/status endpoint (requires valid API key)
        try:
            url = f"{base_url}/queue/status"
            response = requests.get(url, headers=headers, timeout=5)
            
            if response.status_code == 200:
                return True
            elif response.status_code in [401, 403]:
                # Authentication failed - invalid API key
                logger.warning(f"Connection test failed: Invalid API key (HTTP {response.status_code})")
                return False
            else:
                logger.warning(f"Connection test failed: HTTP {response.status_code}")
                return False
        except requests.exceptions.ConnectionError:
            logger.warning(f"Connection test failed: Cannot reach {base_url}")
            return False
        except requests.exceptions.Timeout:
            logger.warning(f"Connection test failed: Request timed out")
            return False
        except Exception as e:
            logger.warning(f"Connection test failed: {e}")
            return False
    
    def _update_keeper_client(self, service_url: str, api_key: str):
        """Update the keeper client with new settings - takes effect immediately."""
        try:
            # Use the new update_credentials method for proper session header update
            self.keeper_client.update_credentials(service_url, api_key)
            logger.ok("Keeper client credentials updated - changes are now active!")
        except Exception as e:
            logger.warning(f"Could not update keeper client: {e}")
    
    def _update_home_with_error(self, client, user_id: str, error: str):
        """Update home view with an error message."""
        try:
            current_settings = self.settings_store.load()
            view = build_app_home_view(
                current_settings=current_settings,
                is_admin=False,
                error_message=error
            )
            client.views_publish(user_id=user_id, view=view)
        except Exception as e:
            logger.error(f"Could not show error in home: {e}")
