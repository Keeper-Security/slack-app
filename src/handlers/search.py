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

"""Handlers for search modal interactions."""

import json
from typing import Dict, Any, Optional
from ..views import build_search_modal
from ..logger import logger
from ..commander_errors import COMMAND_NOT_ALLOWED, COMMANDER_UNAUTHORIZED
from ..utils import notify_commander_unauthorized_or_forbidden


def _search_error_banner(
    client,
    user_id: str,
    search_error: Optional[Dict[str, Any]],
    query: str,
    search_type: str,
) -> str:
    """
    If Commander rejected the search submit with HTTP 401/403, DM the
    user with admin-facing guidance
    """
    if not search_error:
        return ""
    if search_error.get("error_code") not in (COMMAND_NOT_ALLOWED, COMMANDER_UNAUTHORIZED):
        return ""
    return notify_commander_unauthorized_or_forbidden(
        client=client,
        user_id=user_id,
        error=search_error,
        context_lines=[
            f"*Search type:* {search_type}",
            f"*Search query:* `{query}`",
        ],
    )


def _block_self_approval(body: Dict[str, Any], client, action_data: Dict[str, Any]) -> bool:
    """
    Refuse Search-button clicks where the clicker is also the requester.
    """
    approver_id = body.get("user", {}).get("id")
    requester_id = action_data.get("requester_id")
    if not (approver_id and requester_id and approver_id == requester_id):
        return False

    channel_id = (
        (body.get("channel") or {}).get("id")
        or (body.get("container") or {}).get("channel_id")
    )
    if channel_id:
        try:
            client.chat_postEphemeral(
                channel=channel_id,
                user=approver_id,
                text=(
                    ":no_entry_sign: You cannot approve your own request. "
                    "Please ask your admin or another team member to "
                    "review and approve it on your behalf."
                ),
            )
        except Exception as e:
            logger.warning(f"Could not send self-approval ephemeral to {approver_id}: {e}")
    else:
        logger.warning(
            f"Self-approval blocked for {approver_id} but no channel_id found to send ephemeral"
        )
    return True


def handle_search_records(body: Dict[str, Any], client, config, keeper_client):
    """
    Handle search records button click.
    Opens a modal with search results for records.
    """
    trigger_id = body["trigger_id"]
    
    # Extract approval data from button value
    action_data = json.loads(body["actions"][0]["value"])

    # Block self-approval before opening the modal (no trigger_id is consumed
    # and the approval card stays intact for legitimate approvers).
    if _block_self_approval(body, client, action_data):
        return

    # Include message_ts and channel for updating the approval card later
    action_data["message_ts"] = body["message"]["ts"]
    action_data["channel_id"] = body["channel"]["id"]
    
    query = action_data.get("identifier", "")
    
    try:
        # IMMEDIATELY open modal with loading state (must be within 3 seconds of trigger!)
        logger.debug(f"Opening modal immediately with loading state for query: '{query}'")
        loading_modal = build_search_modal(
            query=query,
            search_type="record",
            results=[],  # Empty results initially
            approval_data=action_data,
            loading=True  # Show loading state
        )
        
        response = client.views_open(
            trigger_id=trigger_id,
            view=loading_modal
        )
        logger.debug("Modal opened successfully, now fetching results...")
        
        # Get view_id for updating later
        view_id = response["view"]["id"]
        
        for_one_time_share = action_data.get("type") == "one_time_share"
        logger.debug(f"Searching for records with query: '{query}'")
        records, search_error = keeper_client.search_records(
            query, limit=20, for_one_time_share=for_one_time_share
        )
        logger.debug(f"Got {len(records)} records, updating modal...")

        error_banner = _search_error_banner(
            client=client,
            user_id=body.get("user", {}).get("id", ""),
            search_error=search_error,
            query=query,
            search_type="record",
        )

        # Update the modal with actual results
        updated_modal = build_search_modal(
            query=query,
            search_type="record",
            results=records,
            approval_data=action_data,
            loading=False,  # Show actual results
            error_banner=error_banner or None,
        )
        
        client.views_update(
            view_id=view_id,
            view=updated_modal
        )
        logger.debug("Modal updated with search results")
        
    except Exception as e:
        logger.error(f"Error in search records handler: {e}")
        import traceback
        traceback.print_exc()
        # Could send error message to user


def handle_search_folders(body: Dict[str, Any], client, config, keeper_client):
    """
    Handle search folders button click.
    Opens a modal with search results for folders.
    """
    trigger_id = body["trigger_id"]
    
    # Extract approval data from button value
    action_data = json.loads(body["actions"][0]["value"])

    # Block self-approval before opening the modal (no trigger_id is consumed
    # and the approval card stays intact for legitimate approvers).
    if _block_self_approval(body, client, action_data):
        return
    
    # Include message_ts and channel for updating the approval card later
    action_data["message_ts"] = body["message"]["ts"]
    action_data["channel_id"] = body["channel"]["id"]
    
    query = action_data.get("identifier", "")
    
    try:
        # IMMEDIATELY open modal with loading state (must be within 3 seconds of trigger!)
        logger.debug(f"Opening modal immediately with loading state for folders query: '{query}'")
        loading_modal = build_search_modal(
            query=query,
            search_type="folder",
            results=[],  # Empty results initially
            approval_data=action_data,
            loading=True  # Show loading state
        )
        
        response = client.views_open(
            trigger_id=trigger_id,
            view=loading_modal
        )
        logger.debug("Folder modal opened successfully, now fetching results...")
        
        # Get view_id for updating later
        view_id = response["view"]["id"]
        
        # NOW do the slow search (can take as long as needed)
        logger.debug(f"Searching for folders with query: '{query}'")
        folders, search_error = keeper_client.search_folders(query, limit=20)
        logger.debug(f"Got {len(folders)} folders, updating modal...")

        error_banner = _search_error_banner(
            client=client,
            user_id=body.get("user", {}).get("id", ""),
            search_error=search_error,
            query=query,
            search_type="folder",
        )

        # Update the modal with actual results
        updated_modal = build_search_modal(
            query=query,
            search_type="folder",
            results=folders,
            approval_data=action_data,
            loading=False,  # Show actual results
            error_banner=error_banner or None,
        )
        
        client.views_update(
            view_id=view_id,
            view=updated_modal
        )
        logger.debug("Folder modal updated with search results")
        
    except Exception as e:
        logger.error(f"Error in search folders handler: {e}")
        import traceback
        traceback.print_exc()
        # Could send error message to user
