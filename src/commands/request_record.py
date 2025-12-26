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

"""Handler for /keeper-request-record slash command."""

from typing import Dict, Any
from ..models import RequestType
from ..utils import (
    generate_approval_id, is_valid_uid, parse_command_text,
    sanitize_user_input, MAX_JUSTIFICATION_LENGTH, MAX_IDENTIFIER_LENGTH
)
from ..views import post_approval_request
from ..logger import logger


def handle_request_record(body: Dict[str, Any], client, respond, config, keeper_client):
    """
    Handle /keeper-request-record [record] [reason] command.
    """
    user_id = body["user_id"]
    user_name = body["user_name"]
    text = body.get("text", "").strip()
    
    # Validate input - if no text, open modal for user input
    if not text:
        from ..views import build_request_modal
        channel_id = body.get("channel_id", "")
        response_url = body.get("response_url", "")
        try:
            client.views_open(
                trigger_id=body["trigger_id"],
                view=build_request_modal(user_id, user_name, channel_id, response_url, "record")
            )
        except Exception as e:
            logger.error(f"Failed to open request record modal: {e}")
            respond(
                text="Failed to open request form. Please try again.",
                response_type="ephemeral"
            )
        return
    
    # Parse command text
    identifier, justification = parse_command_text(text)
    
    if not identifier:
        respond(
            text="Please provide a record UID or description.",
            response_type="ephemeral"
        )
        return
    
    # Check if justification is provided
    if not justification:
        respond(
            text=f"Justification is required.\n\n"
                 f"*Usage:* `/keeper-request-record \"{identifier}\" Justification message or ticket number`",
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
    
    # Fetch record details if UID is provided
    record_details = None
    if is_uid:
        logger.info(f"Fetching record details for UID: {identifier}")
        record_details = keeper_client.get_record_by_uid(identifier)
        
        if not record_details:
            # UID not found - send error to user
            respond(
                text=f"*Record Not Found*\n\n"
                     f"No record found with UID: `{identifier}`\n\nPlease verify the UID and try again.",
                response_type="ephemeral"
            )
            return
        
        # Validate it's actually a record, not a folder
        if record_details.record_type in ['folder', 'shared_folder', 'user_folder']:
            logger.warning(f"UID {identifier} is a folder, not a record")
            respond(
                text=f"*Invalid UID Type*\n\n"
                     f"The UID `{identifier}` is a **folder**, not a record.\n\n"
                     f"Please use `/keeper-request-folder {identifier} {justification}` instead.",
                response_type="ephemeral"
            )
            return
    
    # Generate unique approval ID
    approval_id = generate_approval_id()

    try:
        post_approval_request(
            client=client,
            approvals_channel=config.slack.approvals_channel_id,
            approval_id=approval_id,
            requester_id=user_id,
            requester_name=user_name,
            identifier=identifier,
            is_uid=is_uid,
            request_type=RequestType.RECORD,
            justification=justification,
            duration="1h",
            record_details=record_details
        )

        respond(
            text=f"*Record access request submitted!*\n\n"
                 f"Request ID: `{approval_id}`\n"
                 f"Record: `{identifier}`\n"
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
