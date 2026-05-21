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
from typing import Dict, Any
from ..views import build_search_modal
from ..logger import logger
from ..commander_errors import COMMAND_NOT_ALLOWED, COMMANDER_UNAUTHORIZED
from ..utils import notify_commander_unauthorized_or_forbidden


_COMMANDER_REJECTED_CODES = (COMMAND_NOT_ALLOWED, COMMANDER_UNAUTHORIZED)


def _maybe_commander_error_banner(
    client,
    user_id: str,
    search_error: Dict[str, Any],
    query: str,
    search_type: str,
) -> str:
    """
    If Commander rejected the search (HTTP 401/403), DM the user with the
    admin-facing guidance and return a banner string ready for build_search_modal.
    Returns an empty string for any other / no error so the caller can skip
    the banner block.
    """
    if not search_error:
        return ""
    if search_error.get("error_code") not in _COMMANDER_REJECTED_CODES:
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


def handle_search_records(body: Dict[str, Any], client, config, keeper_client):
    """
    Handle search records button click.
    Opens a modal with search results for records.
    """
    trigger_id = body["trigger_id"]
    
    # Extract approval data from button value
    action_data = json.loads(body["actions"][0]["value"])
    
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
        
        # NOW do the slow search (can take as long as needed)
        exclude_pam = action_data.get("type") == "one_time_share"
        logger.debug(f"Searching for records with query: '{query}'")
        records, search_error = keeper_client.search_records(
            query, limit=20, exclude_pam=exclude_pam
        )
        logger.debug(f"Got {len(records)} records, updating modal...")

        error_banner = _maybe_commander_error_banner(
            client=client,
            user_id=body["user"]["id"],
            search_error=search_error,
            query=query,
            search_type="record",
        )

        # Update the modal with actual results (or empty results + banner on
        # Commander 401/403 so the user sees the same actionable guidance that
        # was just DM'd to them).
        updated_modal = build_search_modal(
            query=query,
            search_type="record",
            results=records,
            approval_data=action_data,
            loading=False,
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

        error_banner = _maybe_commander_error_banner(
            client=client,
            user_id=body["user"]["id"],
            search_error=search_error,
            query=query,
            search_type="folder",
        )

        # Update the modal with actual results (or empty results + banner on
        # Commander 401/403).
        updated_modal = build_search_modal(
            query=query,
            search_type="folder",
            results=folders,
            approval_data=action_data,
            loading=False,
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
