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
Main Keeper Slack App orchestrator.
"""

import json
from typing import Optional
from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler

from .config import Config
from .keeper_client import KeeperClient
from .logger import logger
from .commands import (
    handle_request_record,
    handle_request_folder,
    handle_one_time_share,
)
from .handlers import (
    handle_approve_action,
    handle_deny_action,
    handle_search_records,
    handle_search_folders,
    handle_search_modal_submit,
    handle_refine_search_action,
    handle_approve_pedm_request,
    handle_deny_pedm_request,
)
from .handlers.device_approvals import (
    handle_approve_device,
    handle_deny_device,
)
from .app_home import AppHomeHandler


class KeeperSlackApp:
    """
    Keeper Commander Slack Application.
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize Keeper Slack App.
        """
        logger.info("Initializing Keeper Commander Slack App...")
        
        # Load configuration
        self.config = Config(config_path)
        logger.ok("Configuration loaded")
        
        # Initialize Keeper API client
        self.keeper_client = KeeperClient(self.config.keeper)
        logger.ok(f"Keeper client initialized: {self.config.keeper.service_url}")
        
        # Initialize Slack Bolt app
        self.slack_app = App(
            token=self.config.slack.bot_token,
            signing_secret=self.config.slack.signing_secret
        )
        logger.ok("Slack app initialized")
        
        # Register all handlers
        self._register_commands()
        self._register_interactions()
        logger.ok("All handlers registered")
        
        # Initialize Socket Mode handler
        self.socket_handler = SocketModeHandler(
            app=self.slack_app,
            app_token=self.config.slack.app_token
        )
        logger.ok("Socket Mode handler ready")
        logger.info(f"Approval channel: {self.config.slack.approvals_channel_id}")
        
        # Initialize PEDM poller (uses config for interval and enabled flag)
        from .background import PEDMPoller
        self.pedm_poller = PEDMPoller(
            slack_client=self.slack_app.client,
            keeper_client=self.keeper_client,
            config=self.config,
            interval=self.config.pedm.polling_interval_in_sec
        )
        pedm_status = "enabled" if self.config.pedm.enabled else "disabled"
        logger.ok(f"PEDM poller initialized ({pedm_status}, interval: {self.config.pedm.polling_interval_in_sec}s)")
        
        # Initialize Cloud SSO Device Approval poller
        from .background.device_poller import DeviceApprovalPoller
        self.device_poller = DeviceApprovalPoller(
            slack_client=self.slack_app.client,
            keeper_client=self.keeper_client,
            config=self.config,
            interval=self.config.device_approval.polling_interval_in_sec
        )
        device_status = "enabled" if self.config.device_approval.enabled else "disabled"
        logger.ok(f"Cloud SSO Device Approval poller initialized ({device_status}, interval: {self.config.device_approval.polling_interval_in_sec}s)")
        
        # Initialize App Home handler
        self.app_home_handler = AppHomeHandler(self.config, self.keeper_client)
        self._register_app_home_events()
        logger.ok("App Home handler initialized")
    
    def _register_commands(self):
        """Register all slash command handlers."""
        
        @self.slack_app.command("/keeper-request-record")
        def cmd_request_record(ack, body, client, respond):
            ack()
            handle_request_record(body, client, respond, self.config, self.keeper_client)
        
        @self.slack_app.command("/keeper-request-folder")
        def cmd_request_folder(ack, body, client, respond):
            ack()
            handle_request_folder(body, client, respond, self.config, self.keeper_client)
        
        @self.slack_app.command("/keeper-one-time-share")
        def cmd_one_time_share(ack, body, client, respond):
            ack()
            handle_one_time_share(body, client, respond, self.config, self.keeper_client)

    
    def _register_interactions(self):
        """Register all interaction handlers."""
        
        # Approval buttons
        @self.slack_app.action("approve_request")
        def action_approve(ack, body, client):
            ack()
            handle_approve_action(body, client, self.config, self.keeper_client)
        
        @self.slack_app.action("deny_request")
        def action_deny(ack, body, client):
            ack()
            handle_deny_action(body, client, self.config, self.keeper_client)
        
        # PEDM approval buttons
        @self.slack_app.action("approve_pedm_request")
        def action_approve_pedm(ack, body, client):
            ack()
            handle_approve_pedm_request(body, client, self.config, self.keeper_client)
        
        @self.slack_app.action("deny_pedm_request")
        def action_deny_pedm(ack, body, client):
            ack()
            handle_deny_pedm_request(body, client, self.config, self.keeper_client)
        
        # Device approval buttons
        @self.slack_app.action("approve_device")
        def action_approve_device(ack, body, client):
            ack()
            handle_approve_device(body, client, self.config, self.keeper_client)
        
        @self.slack_app.action("deny_device")
        def action_deny_device(ack, body, client):
            ack()
            handle_deny_device(body, client, self.config, self.keeper_client)
        
        # Search buttons
        @self.slack_app.action("search_records")
        def action_search_records(ack, body, client):
            ack()
            handle_search_records(body, client, self.config, self.keeper_client)
        
        @self.slack_app.action("search_folders")
        def action_search_folders(ack, body, client):
            ack()
            handle_search_folders(body, client, self.config, self.keeper_client)
        
        @self.slack_app.action("search_one_time_shares")
        def action_search_one_time_shares(ack, body, client):
            ack()
            handle_search_records(body, client, self.config, self.keeper_client)
        
        # Dropdown selectors on approval cards
        @self.slack_app.action("select_duration")
        def action_select_duration(ack):
            """Acknowledge duration dropdown selection."""
            ack()

        
        @self.slack_app.action("select_permission")
        def action_select_permission(ack, body, client):
            """Handle permission dropdown selection - dynamically show/hide duration."""
            ack()
            
            try:
                import json
                
                # Get selected permission
                selected_permission = body["actions"][0]["selected_option"]["value"]
                
                # Determine if duration should be shown
                PERMANENT_ONLY = ["can_share", "edit_and_share", "change_owner", "manage_users", "manage_all"]
                show_duration = selected_permission not in PERMANENT_ONLY
                
                # Check if this is a modal or a message
                if "view" in body:
                    # MODAL: Rebuild search modal
                    from .views import build_search_modal
                    
                    view = body["view"]
                    metadata = json.loads(view["private_metadata"])
                    
                    updated_modal = build_search_modal(
                        query=metadata.get("query", ""),
                        search_type=metadata.get("search_type", "record"),
                        results=metadata.get("cached_results", []),
                        approval_data=metadata,
                        loading=False,
                        show_duration=show_duration
                    )
                    
                    client.views_update(view_id=view["id"], view=updated_modal)
                    logger.info(f"Updated modal: show_duration={show_duration} for permission={selected_permission}")
                    
                elif "message" in body:
                    # MESSAGE: Update approval card (UID-based requests)
                    from .views import build_permission_selector_block
                    from .utils import get_duration_options
                    from .models import RequestType
                    
                    message = body["message"]
                    channel = body["channel"]["id"]
                    message_ts = message["ts"]
                    blocks = message.get("blocks", [])
                    
                    # Determine request type from header
                    request_type = RequestType.RECORD
                    for block in blocks:
                        if block.get("type") == "header":
                            header_text = block.get("text", {}).get("text", "")
                            if "Folder" in header_text:
                                request_type = RequestType.FOLDER
                            break
                    
                    # Rebuild blocks with updated duration visibility
                    new_blocks = []
                    for block in blocks:
                        block_id = block.get("block_id", "")
                        accessory = block.get("accessory", {})
                        action_id = accessory.get("action_id", "")
                        
                        # Skip old duration selector block
                        if block_id == "duration_selector" or action_id == "select_duration":
                            continue
                        
                        # Skip old permanent notice context block
                        if block.get("type") == "context":
                            elements = block.get("elements", [])
                            if elements and "Permanent Access" in elements[0].get("text", ""):
                                continue
                        
                        # After permission selector, add duration or permanent notice
                        if action_id == "select_permission":
                            new_blocks.append(block)  # Keep permission selector
                            
                            if show_duration:
                                new_blocks.append({
                                    "type": "section",
                                    "block_id": "duration_selector",
                                    "text": {"type": "mrkdwn", "text": "*Grant Access For:*"},
                                    "accessory": {
                                        "type": "static_select",
                                        "action_id": "select_duration",
                                        "options": get_duration_options(),
                                        "initial_option": {"text": {"type": "plain_text", "text": "1 hour"}, "value": "1h"}
                                    }
                                })
                            else:
                                new_blocks.append({
                                    "type": "context",
                                    "elements": [{"type": "mrkdwn", "text": "ℹ️ *Permanent Access:* This permission does not support time limits."}]
                                })
                        else:
                            new_blocks.append(block)
                    
                    # Update the message
                    client.chat_update(
                        channel=channel,
                        ts=message_ts,
                        blocks=new_blocks,
                        text="Access Request"
                    )
                    logger.info(f"Updated message: show_duration={show_duration} for permission={selected_permission}")
                    
            except Exception as e:
                logger.error(f"Failed to update on permission change: {e}")
                import traceback
                traceback.print_exc()

        
        # Search modal action buttons
        @self.slack_app.action("refine_search_action")
        def action_refine_search(ack, body, client):
            ack()
            handle_refine_search_action(body, client, self.config, self.keeper_client)
        
        @self.slack_app.action("create_new_record_action")
        def action_create_new_record(ack, body, client):
            ack()
            from .handlers.modals import handle_create_new_record_action
            handle_create_new_record_action(body, client, self.config, self.keeper_client)
        
        @self.slack_app.action("self_destructive_checkbox")
        def action_self_destruct_checkbox(ack, body, client):
            """Handle self-destruct checkbox toggle to show/hide expiration field."""
            ack()
            
            try:
                # Get current checkbox state
                selected_options = body["actions"][0].get("selected_options", [])
                is_checked = len(selected_options) > 0

                # Get modal data
                view = body["view"]
                view_id = view["id"]
                metadata = json.loads(view["private_metadata"])
                
                # Rebuild modal with expiration field shown/hidden
                from .views import build_create_record_modal
                updated_modal = build_create_record_modal(
                    approval_data=metadata,
                    original_query="",
                    show_expiration=is_checked  # Show dropdown only if checked
                )
                
                # Update the modal
                client.views_update(
                    view_id=view_id,
                    view=updated_modal
                )

            except Exception as e:
                logger.error(f"Error handling self-destruct checkbox: {e}")
                import traceback
                traceback.print_exc()
        
        # Modal submissions
        @self.slack_app.view("search_modal_submit")
        def view_search_submit(ack, body, client):
            # Pass ack to handler so it can show errors in modal
            try:
                handle_search_modal_submit(ack, body, client, self.config, self.keeper_client)
            except Exception as e:
                logger.error(f"Error processing search modal submission: {e}")
                import traceback
                traceback.print_exc()
                # Acknowledge with error if handler failed
                try:
                    ack()
                except:
                    pass
        
        @self.slack_app.view("create_record_modal_submit")
        def view_create_record_submit(ack, body, client):
            ack()
            try:
                from .handlers.modals import handle_create_record_submit
                handle_create_record_submit(body, client, self.config, self.keeper_client)
            except Exception as e:
                logger.error(f"Error creating record: {e}")
                import traceback
                traceback.print_exc()
    
    def _register_app_home_events(self):
        """Register App Home tab event handlers."""
        
        @self.slack_app.event("app_home_opened")
        def handle_app_home_opened(client, event):
            """Handle when user opens the App Home tab."""
            self.app_home_handler.handle_app_home_opened(client, event)
        
        @self.slack_app.action("test_keeper_connection")
        def action_test_connection(ack, body, client):
            """Handle Test Connection button click."""
            self.app_home_handler.handle_test_connection(ack, body, client)
        
        @self.slack_app.action("save_keeper_settings")
        def action_save_settings(ack, body, client):
            """Handle Save Settings button click."""
            self.app_home_handler.handle_save_settings(ack, body, client)

    
    def start(self):
        """
        Start the Slack app in Socket Mode.
        """
        print("\n" + "="*60)
        print("Starting Keeper Commander Slack App")
        print("="*60)
        logger.ok("Socket Mode enabled")
        logger.info("Listening for Slack commands and interactions...")
        print("="*60 + "\n")
        
        # Check Keeper connectivity
        if self.keeper_client.health_check():
            logger.ok("Keeper Service Mode is accessible\n")
        else:
            logger.warning("Cannot reach Keeper Service Mode")
            print(f"   URL: {self.config.keeper.service_url}")
            print("   The app will start but commands may fail.\n")
        
        # Start PEDM poller in background (if enabled in config)
        if self.config.pedm.enabled:
            try:
                self.pedm_poller.start()
            except Exception as e:
                logger.warning(f"Could not start PEDM poller: {e}")
        else:
            logger.info("PEDM polling is disabled (set pedm.enabled=true in config to enable)")
        
        # Start Cloud SSO Device Approval poller in background (if enabled in config)
        if self.config.device_approval.enabled:
            try:
                self.device_poller.start()
            except Exception as e:
                logger.warning(f"Could not start Cloud SSO Device Approval poller: {e}")
        else:
            logger.info("Cloud SSO Device Approval polling is disabled (set device_approval.enabled=true in config to enable)")
        
        try:
            self.socket_handler.start()
        except KeyboardInterrupt:
            logger.info("Shutting down Keeper Slack App...")
            print("Goodbye!\n")


# Entry point for running directly
if __name__ == "__main__":
    app = KeeperSlackApp()
    app.start()
