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

"""Handlers for Device Approval interactions."""

from typing import Dict, Any
from ..logger import logger


def handle_approve_device(body: Dict[str, Any], client, config, keeper_client):
    """
    Handle device approve button click.
    
    Approves the device and updates the Slack message.
    """
    approver_id = body["user"]["id"]
    approver_name = body["user"]["name"]
    
    # Extract device ID from button value
    device_id = body["actions"][0]["value"]
    
    logger.info(f"Device approval action by {approver_name} for {device_id}")
    
    try:
        # Approve the device
        result = keeper_client.approve_device(device_id)
        
        if result.get('success'):
            # Update approval message
            status_text = f"*Status:* Approved by <@{approver_id}>\n*Updated:* {_format_timestamp()}"
            
            original_blocks = body["message"]["blocks"]
            updated_blocks = [b for b in original_blocks if b.get("type") != "actions"]
            
            # Add status section
            updated_blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": status_text
                }
            })
            
            client.chat_update(
                channel=body["channel"]["id"],
                ts=body["message"]["ts"],
                blocks=updated_blocks,
                text=status_text
            )
            
            logger.ok(f"Device {device_id} approved by {approver_id}")
        else:
            # Update with error
            error_msg = result.get('error', 'Unknown error')
            status_text = f"*Status:* Approval failed - {error_msg}"
            
            original_blocks = body["message"]["blocks"]
            updated_blocks = [b for b in original_blocks if b.get("type") != "actions"]
            updated_blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": status_text}
            })
            
            client.chat_update(
                channel=body["channel"]["id"],
                ts=body["message"]["ts"],
                blocks=updated_blocks,
                text=status_text
            )
            
            logger.error(f"Failed to approve device {device_id}: {error_msg}")
            
    except Exception as e:
        logger.error(f"Exception in device approve handler: {e}")
        import traceback
        traceback.print_exc()


def handle_deny_device(body: Dict[str, Any], client, config, keeper_client):
    """
    Handle device deny button click.
    
    Denies the device and updates the Slack message.
    """
    approver_id = body["user"]["id"]
    approver_name = body["user"]["name"]
    
    # Extract device ID from button value
    device_id = body["actions"][0]["value"]
    
    logger.info(f"Device denial action by {approver_name} for {device_id}")
    
    try:
        # Deny the device
        result = keeper_client.deny_device(device_id)
        
        if result.get('success'):
            # Update approval message
            status_text = f"*Status:* Denied by <@{approver_id}>\n*Updated:* {_format_timestamp()}"
            
            # Remove action buttons
            original_blocks = body["message"]["blocks"]
            updated_blocks = [b for b in original_blocks if b.get("type") != "actions"]
            
            # Add status section
            updated_blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": status_text
                }
            })
            
            client.chat_update(
                channel=body["channel"]["id"],
                ts=body["message"]["ts"],
                blocks=updated_blocks,
                text=status_text
            )
            
            logger.ok(f"Device {device_id} denied by {approver_id}")
        else:
            # Update with error
            error_msg = result.get('error', 'Unknown error')
            status_text = f"*Status:* Denial failed - {error_msg}"
            
            original_blocks = body["message"]["blocks"]
            updated_blocks = [b for b in original_blocks if b.get("type") != "actions"]
            updated_blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": status_text}
            })
            
            client.chat_update(
                channel=body["channel"]["id"],
                ts=body["message"]["ts"],
                blocks=updated_blocks,
                text=status_text
            )
            
            logger.error(f"Failed to deny device {device_id}: {error_msg}")
            
    except Exception as e:
        logger.error(f"Exception in device deny handler: {e}")
        import traceback
        traceback.print_exc()


def _format_timestamp() -> str:
    """Format current timestamp for display."""
    from datetime import datetime
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

