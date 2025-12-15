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
        logger.debug(f"Searching for records with query: '{query}'")
        records = keeper_client.search_records(query, limit=20)
        logger.debug(f"Got {len(records)} records, updating modal...")
        
        # Update the modal with actual results
        updated_modal = build_search_modal(
            query=query,
            search_type="record",
            results=records,
            approval_data=action_data,
            loading=False  # Show actual results
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
        folders = keeper_client.search_folders(query, limit=20)
        logger.debug(f"Got {len(folders)} folders, updating modal...")
        
        # Update the modal with actual results
        updated_modal = build_search_modal(
            query=query,
            search_type="folder",
            results=folders,
            approval_data=action_data,
            loading=False  # Show actual results
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
