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

"""Handler for /keeper-request-folder slash command."""

from typing import Dict, Any
from ..models import RequestType
from ..utils import (
    generate_approval_id, is_valid_uid, parse_command_text,
    sanitize_user_input, MAX_JUSTIFICATION_LENGTH, MAX_IDENTIFIER_LENGTH
)
from ..views import post_approval_request
from ..logger import logger


def handle_request_folder(body: Dict[str, Any], client, respond, config, keeper_client):
    """
    Handle /keeper-request-folder [folder] [reason] command.
    """
    user_id = body["user_id"]
    user_name = body["user_name"]
    text = body.get("text", "").strip()
    
    # Validate input
    if not text:
        respond(
            text="*Usage:* `/keeper-request-folder \"Folder UID or Description\" Justification message or ticket number`\n\n"
                 "*Examples:*\n"
                 "• `/keeper-request-folder kF8zQ2Nm5Wx9PtR3sY7a Need staging access`\n"
                 "• `/keeper-request-folder \"Staging Team Folder\" JIRA-1234 Need access for deployment`\n\n"
                 "*Tip:* Quotes are required for descriptions with spaces, but optional for UIDs",
            response_type="ephemeral"
        )
        return

    identifier, justification = parse_command_text(text)
    
    if not identifier:
        respond(
            text="Please provide a folder UID or description.",
            response_type="ephemeral"
        )
        return
    
    # Check if justification is provided
    if not justification:
        respond(
            text=f"Justification is required.\n\n"
                 f"*Usage:* `/keeper-request-folder \"{identifier}\" Justification message or ticket number`",
            response_type="ephemeral"
        )
        return
    
    # Security: Sanitize and validate inputs
    identifier, id_valid, id_error = sanitize_user_input(identifier, MAX_IDENTIFIER_LENGTH)
    if not id_valid:
        respond(text=f"*Invalid Input*\n\n{id_error}", response_type="ephemeral")
        return
    
    justification, just_valid, just_error = sanitize_user_input(justification, MAX_JUSTIFICATION_LENGTH)
    if not just_valid:
        respond(text=f"*Invalid Input*\n\n{just_error}", response_type="ephemeral")
        return
    
    # Determine if UID or description
    is_uid = is_valid_uid(identifier)
    
    # Fetch folder details if UID is provided
    folder_details = None
    if is_uid:
        logger.info(f"Fetching folder details for UID: {identifier}")
        folder_details = keeper_client.get_folder_by_uid(identifier)
        
        if not folder_details:
            # UID not found - send error to user
            respond(
                text=f"*Folder Not Found*\n\n"
                     f"No folder found with UID: `{identifier}`\n\nPlease verify the UID and try again.",
                response_type="ephemeral"
            )
            return
        
        # Validate it's actually a folder, not a record
        if folder_details.folder_type == 'record':
            logger.warning(f"UID {identifier} is a record, not a folder")
            respond(
                text=f"*Invalid UID Type*\n\n"
                     f"The UID `{identifier}` is a **record**, not a folder.\n\n"
                     f"Please use `/keeper-request-record {identifier} {justification}` instead.",
                response_type="ephemeral"
            )
            return
    
    # Generate unique approval ID
    approval_id = generate_approval_id()
    
    # Post approval request to approvals channel
    try:
        post_approval_request(
            client=client,
            approvals_channel=config.slack.approvals_channel_id,
            approval_id=approval_id,
            requester_id=user_id,
            requester_name=user_name,
            identifier=identifier,
            is_uid=is_uid,
            request_type=RequestType.FOLDER,
            justification=justification,
            duration="1h",  # Default minimum (approver can change)
            folder_details=folder_details
        )
        

        respond(
            text=f"*Folder access request submitted!*\n\n"
                 f"Request ID: `{approval_id}`\n"
                 f"Folder: `{identifier}`\n"
                 f"Justification: {justification}\n\n"
                 f"Your request has been sent to <#{config.slack.approvals_channel_id}> for approval.\n"
                 f"Once approved, the details will be sent to you via DM.",
            response_type="ephemeral"
        )
            
    except Exception as e:
        logger.error(f"Error posting approval request: {e}")
        

        respond(
            text=f"*Failed to submit access request*\n\n"
                 f"Please try again or contact support.\n\nError: {str(e)}",
            response_type="ephemeral"
        )
