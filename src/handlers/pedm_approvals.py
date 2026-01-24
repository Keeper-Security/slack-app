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

"""Handlers for PEDM approval interactions."""

from typing import Dict, Any
from ..logger import logger


def handle_approve_pedm_request(body: Dict[str, Any], client, config, keeper_client):
    """
    Handle PEDM approve button click.
    """
    approver_id = body["user"]["id"]
    approver_name = body["user"]["name"]
    
    # Extract approval UID from button value
    approval_uid = body["actions"][0]["value"]
    
    logger.info(f"PEDM approval action by {approver_name} for {approval_uid}")
    
    try:
        # Approve the PEDM request
        result = keeper_client.approve_pedm_request(approval_uid)
        
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
            
            logger.ok(f"PEDM request {approval_uid} approved by {approver_id}")
        else:
            # Check if request was already processed
            if result.get('already_processed'):
                status_text = f"*Status:* Already processed (approved/denied elsewhere)\n*Checked by:* <@{approver_id}>\n*Updated:* {_format_timestamp()}"
                logger.warning(f"PEDM request {approval_uid} was already processed")
            else:
                # Update with error
                error_msg = result.get('error', 'Unknown error')
                status_text = f"*Status:* Approval failed - {error_msg}"
                logger.error(f"Failed to approve PEDM request {approval_uid}: {error_msg}")
            
            # Update the message with status (for both already_processed and error cases)
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
            
    except Exception as e:
        logger.error(f"Exception in PEDM approve handler: {e}", exc_info=True)


def handle_deny_pedm_request(body: Dict[str, Any], client, config, keeper_client):
    """
    Handle PEDM deny button click.
    
    Denies the PEDM request and updates the card.
    """
    approver_id = body["user"]["id"]
    approver_name = body["user"]["name"]
    
    # Extract approval UID from button value
    approval_uid = body["actions"][0]["value"]
    
    logger.info(f"PEDM denial action by {approver_name} for {approval_uid}")
    
    try:
        # Deny the PEDM request
        result = keeper_client.deny_pedm_request(approval_uid)
        
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
            
            logger.ok(f"PEDM request {approval_uid} denied by {approver_id}")
        else:
            # Check if request was already processed
            if result.get('already_processed'):
                status_text = f"*Status:* Already processed (approved/denied elsewhere)\n*Checked by:* <@{approver_id}>\n*Updated:* {_format_timestamp()}"
                logger.warning(f"PEDM request {approval_uid} was already processed")
            else:
                # Update with error
                error_msg = result.get('error', 'Unknown error')
                status_text = f"*Status:* Denial failed - {error_msg}"
                logger.error(f"Failed to deny PEDM request {approval_uid}: {error_msg}")
            
            # Update the message with status (for both already_processed and error cases)
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
            
    except Exception as e:
        logger.error(f"Exception in PEDM deny handler: {e}", exc_info=True)


def _format_timestamp() -> str:
    """Format current timestamp for display."""
    from datetime import datetime
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')
