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

"""Handlers for modal dialog submissions."""

import json
import requests
from typing import Dict, Any
from ..models import PermissionLevel, RequestType
from ..views import update_approval_message, send_access_granted_dm, post_approval_request
from ..utils import (
    parse_duration_to_seconds, format_duration, get_user_email_from_slack,
    generate_approval_id, is_valid_uid, sanitize_user_input,
    MAX_JUSTIFICATION_LENGTH, MAX_IDENTIFIER_LENGTH
)
from ..logger import logger


def _send_ephemeral_response(response_url: str, text: str) -> bool:
    """
    Send ephemeral response using the slash command's response_url.
    """
    try:
        resp = requests.post(
            response_url,
            json={
                "text": text,
                "response_type": "ephemeral"
            },
            timeout=5
        )
        return resp.status_code == 200
    except Exception as e:
        logger.warning(f"Failed to send response via response_url: {e}")
        return False


def handle_search_modal_submit(ack, body: Dict[str, Any], client, config, keeper_client):
    """
    Handle search modal submission.
    Can either re-search with new query or approve with selected item.
    """
    # Extract approval data from private metadata
    approval_data = json.loads(body["view"]["private_metadata"])
    
    # Extract values from form
    values = body["view"]["state"]["values"]
    
    # Check if user modified search query
    new_query = values.get("search_query", {}).get("update_search_query", {}).get("value", "").strip()
    search_type = approval_data.get("search_type", approval_data.get("type", "record"))
    
    logger.debug(f"Modal submit - new_query: '{new_query}', search_type: {search_type}")
    
    # Check if radio buttons block exists (means we have results)
    selected_item_block = values.get("selected_item")
    has_results = selected_item_block is not None
    
    logger.debug(f"Has results block: {has_results}")
    
    if not has_results:
        # No results yet - user is searching
        logger.debug(f"No results block - running search with query: '{new_query}'")
        
        # Acknowledge immediately for search operations
        ack()
        
        # Run search
        if search_type == "record":
            results = keeper_client.search_records(new_query, limit=20)
        else:
            results = keeper_client.search_folders(new_query, limit=20)
        
        # Rebuild and update modal with results using API call
        from ..views import build_search_modal
        updated_modal = build_search_modal(
            query=new_query,
            search_type=search_type,
            results=results,
            approval_data=approval_data
        )
        
        logger.debug(f"Updating modal with {len(results)} results")
        
        try:
            client.views_update(
                view_id=body["view"]["id"],
                view=updated_modal
            )
            logger.debug("Modal updated successfully")
        except Exception as e:
            logger.error(f"Failed to update modal: {e}")
        
        return  # Done with search update

    selected_item = selected_item_block.get("item_selection", {}).get("selected_option")
    logger.debug(f"Selected item: {selected_item}")
    
    # If no item selected, show error in modal
    if not selected_item:
        logger.warning("No item selected - user submitted without selecting")
        ack(response_action="update", view={
            "type": "modal",
            "title": {"type": "plain_text", "text": "Selection Required"},
            "close": {"type": "plain_text", "text": "Close"},
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "*Please select an item before approving.*\n\nGo back and select a record/folder from the list."
                    }
                }
            ]
        })
        return
    
    # Item selected - acknowledge IMMEDIATELY (Slack requires ack within 3 seconds)
    # This closes the modal; errors will be shown in a new modal
    ack()
    
    selected_uid = selected_item["value"]
    
    # Get record title from the selected item or metadata
    record_title = selected_item.get("text", {}).get("text", "").split(" (")[0] if selected_item else f"Record {selected_uid}"
    if not record_title or record_title.startswith("Record "):
        record_title = approval_data.get('newly_created_title', approval_data.get('record_title', f"Record {selected_uid}"))
    
    # Check if this is a self-destruct record
    is_self_destruct = approval_data.get('create_self_destruct', False)
    
    # Extract permission and duration
    if is_self_destruct:
        # Self-destruct records: use duration from creation, always view-only
        logger.info("Self-destruct record detected - sharing with view-only access")
        permission = PermissionLevel.VIEW_ONLY
        self_destruct_duration_str = approval_data.get('self_destruct_duration', '1h')
        duration_seconds = parse_duration_to_seconds(self_destruct_duration_str)
        duration_value = self_destruct_duration_str
        duration_text = format_duration(self_destruct_duration_str)
        editable = False
    else:
        # Normal records: use admin-selected permission and duration
        permission_block = values.get("permission_selector", {}).get("select_permission", {})
        permission_value = permission_block.get("selected_option", {}).get("value", "view_only")
        permission = PermissionLevel(permission_value)
        
        # For one-time shares, convert permission to editable flag
        editable = (permission_value == PermissionLevel.CAN_EDIT.value)
        
        # Some permissions are always permanent (no duration)
        PERMANENT_ONLY_PERMISSIONS = [
            # Record permissions (permanent)
            PermissionLevel.CAN_SHARE.value,
            PermissionLevel.EDIT_AND_SHARE.value,
            PermissionLevel.CHANGE_OWNER.value,
            # Folder permissions (permanent)
            PermissionLevel.MANAGE_USERS.value,
            PermissionLevel.MANAGE_ALL.value
        ]
        
        if permission_value in PERMANENT_ONLY_PERMISSIONS:
            # Force permanent access for these permissions
            duration_seconds = None
            duration_value = "permanent"
            duration_text = "No Expiration"
            logger.info(f"{permission_value} is permanent-only, ignoring duration selector")
        else:
            # Normal duration handling for View Only and Can Edit
            duration_block = values.get("grant_duration", {}).get("grant_duration_select", {})
            # Handle the case where selected_option is null (when field is cleared)
            selected_option = duration_block.get("selected_option") or {}
            duration_value = selected_option.get("value")
            
            # Check if duration was cleared/not selected or set to permanent
            if duration_value == "permanent":
                # User explicitly selected "No Expiration"
                duration_seconds = None
                duration_text = "No Expiration"
            elif not duration_value:
                # User cleared or didn't select duration (optional field) - treat as permanent
                duration_seconds = None
                duration_value = "permanent"
                duration_text = "No Expiration"
            else:
                # Normal duration value selected
                duration_seconds = parse_duration_to_seconds(duration_value)
                duration_text = format_duration(duration_value)
    
    # Get approver info
    approver_id = body["user"]["id"]
    approver_name = body["user"]["name"]
    
    # Grant access
    requester_id = approval_data["requester_id"]
    request_type = approval_data["type"]
    approval_id = approval_data["approval_id"]
    
    # Get user's real email from Slack
    user_email = get_user_email_from_slack(client, requester_id)
    
    try:
        if request_type == "record":
            result = keeper_client.grant_record_access(
                record_uid=selected_uid,
                user_email=user_email,
                permission=permission,
                duration_seconds=duration_seconds
            )
        elif request_type == "folder":
            result = keeper_client.grant_folder_access(
                folder_uid=selected_uid,
                user_email=user_email,
                permission=permission,
                duration_seconds=duration_seconds
            )
        elif request_type == "one_time_share":
            # Create one-time share link with editable permission
            result = keeper_client.create_one_time_share(
                record_uid=selected_uid,
                duration_seconds=duration_seconds,
                editable=editable
            )
        else:
            result = {'success': False, 'error': f'Unknown request type: {request_type}'}
        
        if result.get('success'):
            # Modal already closed via early ack()
            from ..views import send_share_link_dm
            
            # Send appropriate DM based on request type
            if request_type == "one_time_share":
                # Send one-time share link
                send_share_link_dm(
                client=client,
                user_id=requester_id,
                    record_uid=selected_uid,
                    share_url=result.get('share_url'),
                    record_title=record_title,
                    expires_at=result.get('expires_at'),
                    approval_id=approval_id
                )
                logger.info(f"Approval {approval_id}: Created one-time share via search modal by {approver_id}")
            else:
                # Notify requester with access granted (works for both regular and self-destruct records)
                # Build message with self-destruct note if applicable
                access_message = f"*Access Granted!*\n\n" \
                                f"*Request ID:* `{approval_id}`\n" \
                                f"*Record:* {record_title}\n" \
                                f"*UID:* `{selected_uid}`\n" \
                                f"*Access Type:* Direct vault access\n" \
                                f"*Permission:* {permission.value}\n" \
                                f"*Expires:* {result.get('expires_at', duration_text)}"
                
                # Add self-destruct notice if applicable
                if is_self_destruct:
                    access_message += f"\n\n*Self-Destruct Record*\n" \
                                    f"This record will automatically delete from the vault after {duration_text}."
                
                from ..utils import send_dm
                send_dm(client, requester_id, access_message)
                logger.info(f"Approval {approval_id}: Granted via search modal by {approver_id}" + 
                      (" (self-destruct)" if is_self_destruct else ""))
            
            # Update original approval card to show approved status
            message_ts = approval_data.get("message_ts")
            channel_id = approval_data.get("channel_id", config.slack.approvals_channel_id)
            
            if message_ts:
                try:
                    from datetime import datetime
                    
                    # Get expiration info from result
                    expires_at = result.get('expires_at', 'Never')
                    is_permanent = duration_value == "permanent"
                    
                    # Create status message based on request type
                    if request_type == "one_time_share":
                        status_msg = f"*One-Time Share Link Created*\nLink sent to requester • Expires: {expires_at}"
                        approval_text = "One-Time Share Request Approved"
                    else:
                        if is_permanent:
                            status_msg = "*Access Granted (No Expiration)*\nAccess remains active indefinitely"
                        else:
                            status_msg = f"*Temporary Access Granted*\nAccess will expire on *{expires_at}*"
                        
                        # Add self-destruct note if applicable
                        if is_self_destruct:
                            status_msg += f"\n\n*Self-Destruct Record*\nRecord will auto-delete after {duration_text}"
                            approval_text = "Self-Destruct Record Access Approved"
                        else:
                            approval_text = "Access Request Approved"
                    
                    client.chat_update(
                        channel=channel_id,
                        ts=message_ts,
                        text=f"Request approved by <@{approver_id}>",
                        blocks=[
                            {
                                "type": "header",
                                "text": {
                                    "type": "plain_text",
                                    "text": approval_text,
                                    "emoji": True
                                }
                            },
                            {
                                "type": "section",
                                "text": {
                                    "type": "mrkdwn",
                                    "text": f"*Record:* `{selected_uid}`\n"
                                            f"*Requester:* <@{requester_id}>\n"
                                            f"*Approved by:* <@{approver_id}>"
                                }
                            },
                            {
                                "type": "divider"
                            },
                            {
                                "type": "section",
                                "text": {
                                    "type": "mrkdwn",
                                    "text": status_msg
                                }
                            },
                            {
                                "type": "context",
                                "elements": [
                                    {
                                        "type": "mrkdwn",
                                        "text": f"Access granted via search • {datetime.now().strftime('%B %d, %Y at %I:%M %p')}"
                                    }
                                ]
                            }
                        ]
                    )
                    logger.info(f"Updated approval card {approval_id} (message_ts: {message_ts})")
                except Exception as update_error:
                    logger.error(f"Failed to update approval card: {update_error}")
            else:
                logger.warning("No message_ts found in approval_data, cannot update card")
            
            # Modal closed via early ack - success!
            logger.info(f"Access granted successfully for {approval_id}")
        else:
            # Failed to grant access - show error to approver
            error_msg = result.get('error', 'Unknown error')
            logger.error(f"Failed to grant access: {error_msg}")
            
            # Update the original approval card with error status
            if "channel_id" in approval_data and "message_ts" in approval_data:
                try:
                    from ..views import update_approval_message
                    update_approval_message(
                        client=client,
                        channel_id=approval_data["channel_id"],
                        message_ts=approval_data["message_ts"],
                        status=f"Approval failed: {error_msg}",
                        original_blocks=[]
                    )
                except Exception as update_error:
                    logger.error(f"Failed to update approval card: {update_error}")
            
            # Open a new modal to show the error to approver (original modal already closed)
            try:
                client.views_open(
                    trigger_id=body.get("trigger_id"),
                    view={
                        "type": "modal",
                        "title": {"type": "plain_text", "text": "Error"},
                        "close": {"type": "plain_text", "text": "Close"},
                        "blocks": [
                            {
                                "type": "header",
                                "text": {"type": "plain_text", "text": "Failed to Grant Access"}
                            },
                            {
                                "type": "section",
                                "text": {
                                    "type": "mrkdwn",
                                    "text": error_msg
                                }
                            },
                            {"type": "divider"},
                            {
                                "type": "context",
                                "elements": [{
                                    "type": "mrkdwn",
                                    "text": "Please try again with different settings if needed, or contact the requester directly."
                                }]
                            }
                        ]
                    }
                )
            except Exception as modal_error:
                # If we can't open a modal (trigger_id expired), send DM to approver
                logger.warning(f"Could not open error modal: {modal_error}")
                from ..utils import send_error_dm
                send_error_dm(client, approver_id, "Failed to Grant Access", error_msg)
            
    except Exception as e:
        logger.error(f"Error granting access from search modal: {e}")
        import traceback
        traceback.print_exc()
        
        # Try to show error - send DM as fallback since ack may have been called
        from ..utils import send_error_dm
        send_error_dm(
            client, body["user"]["id"],
            "System Error",
            f"An error occurred while processing your approval: {str(e)}"
        )


def handle_refine_search_action(body: Dict[str, Any], client, config, keeper_client):
    """
    Handle 'Refine Search' button click in search modal.
    Re-runs search with the updated query from the search field.
    """
    # Extract view data
    view = body["view"]
    values = view["state"]["values"]
    approval_data = json.loads(view["private_metadata"])
    
    # Get updated search query
    new_query = values.get("search_query", {}).get("update_search_query", {}).get("value", "").strip()
    search_type = approval_data.get("search_type", "record")
    
    logger.debug(f"Refining search with query: '{new_query}'")
    
    # Re-run search
    if search_type == "record":
        results = keeper_client.search_records(new_query, limit=20)
    else:
        results = keeper_client.search_folders(new_query, limit=20)
    
    # Build updated modal
    from ..views import build_search_modal
    updated_modal = build_search_modal(
        query=new_query,
        search_type=search_type,
        results=results,
        approval_data=approval_data
    )
    
    logger.debug(f"Updating modal with {len(results)} results")
    
    # Update the modal
    try:
        client.views_update(
            view_id=view["id"],
            view=updated_modal
        )
    except Exception as e:
        logger.error(f"Error updating search modal: {e}")


def handle_create_new_record_action(body: Dict[str, Any], client, config, keeper_client):
    """
    Handle 'Create New Record' button click in search modal.
    Opens a modal for creating a new record.
    """
    from ..views import build_create_record_modal
    
    # Extract metadata from button value
    value = body["actions"][0].get("value", "{}")
    approval_data = json.loads(value)
    
    # Get the current search query from the view state
    view_state = body.get("view", {}).get("state", {}).get("values", {})
    current_query = view_state.get("search_query", {}).get("update_search_query", {}).get("value", "")
    
    try:
        # Open the create record modal (stacked on top) - initially without expiration dropdown
        client.views_push(
            trigger_id=body["trigger_id"],
            view=build_create_record_modal(approval_data, current_query, show_expiration=False)
        )
    except Exception as e:
        logger.error(f"Failed to open create record modal: {e}")


def handle_create_record_submit(body: Dict[str, Any], client, config, keeper_client):
    """
    Handle create record modal submission.
    Creates the record, then returns to search modal with new record pre-selected.
    """
    # Extract approval metadata
    metadata = json.loads(body["view"]["private_metadata"])
    requester_id = metadata.get('requester_id')
    search_type = metadata.get('search_type', 'record')
    
    # IMMEDIATELY show loading state on previous view (before any slow operations)
    view_id = body["view"].get("previous_view_id")
    if view_id:
        try:
            from ..views import build_search_modal
            loading_modal = build_search_modal(
                query="Creating record...",
                search_type=search_type,
                results=[],
                approval_data=metadata,
                loading=True  # Show loading state
            )
            update_response = client.views_update(
                view_id=view_id,
                view=loading_modal
            )
            # Get the updated view_id from the response
            if update_response.get('ok'):
                view_id = update_response['view']['id']
                logger.debug(f"Loading state shown, updated view_id: {view_id}")
            else:
                logger.warning("Loading state update returned ok=False")
        except Exception as e:
            logger.error(f"Failed to show initial loading state: {e}")
            view_id = None  # Clear view_id if loading update failed
    
    # Extract form values
    values = body["view"]["state"]["values"]
    
    title = (values.get("record_title", {}).get("title_input", {}).get("value") or "").strip()
    login = (values.get("record_login", {}).get("login_input", {}).get("value") or "").strip()
    password = (values.get("record_password", {}).get("password_input", {}).get("value") or "").strip()
    url = (values.get("record_url", {}).get("url_input", {}).get("value") or "").strip()
    notes = (values.get("record_notes", {}).get("notes_input", {}).get("value") or "").strip()
    
    # Extract self-destruct checkbox and expiration
    self_destruct_enabled = False
    self_destruct_duration = None
    
    # Check if checkbox is checked (from actions block)
    checkbox_options = values.get("self_destructive_actions", {}).get("self_destructive_checkbox", {}).get("selected_options", [])
    if checkbox_options and len(checkbox_options) > 0:
        self_destruct_enabled = True
        
        # Get expiration duration (from input block)
        expiration_value = values.get("link_expiration", {}).get("expiration_select", {}).get("selected_option", {}).get("value")
        if expiration_value:
            self_destruct_duration = expiration_value  # e.g., "1h", "24h", "7d", etc.
        
        # Mark in metadata that self-destruct is being used
        metadata['create_self_destruct'] = True
        metadata['self_destruct_duration'] = self_destruct_duration
    
    if not title:
        # Return error to modal
        return {
            "response_action": "errors",
            "errors": {
                "record_title": "Title is required"
            }
        }
    
    try:
        # Create the record
        logger.info(f"Creating record '{title}' for requester {requester_id}" + (f" with self-destruct" if self_destruct_enabled else ""))
        generate_password = not password
        
        create_result = keeper_client.create_record(
            title=title,
            login=login or None,
            password=password or None,
            url=url or None,
            notes=notes or None,
            generate_password=generate_password,
            self_destruct_duration=self_destruct_duration if self_destruct_enabled else None
        )
        
        if not create_result.get('success'):
            # Show error in modal
            error_msg = create_result.get('error', 'Unknown error')
            # Send DM with error since we can't easily show it in modal after ack
            from ..utils import send_error_dm
            user_id = body["user"]["id"]
            send_error_dm(
                client, user_id,
                "Failed to create record",
                error_msg
            )
            return
        
        record_uid = create_result.get('record_uid')
        is_self_destruct = create_result.get('self_destruct', False)
        
        if not record_uid:
            logger.warning("Record created but UID not found")
            return
        
        logger.ok(f"Record created: {record_uid}" + (" (self-destruct)" if is_self_destruct else ""))
        logger.debug(f"view_id from body: {view_id}")
        
        # Return to search modal with new record pre-selected (works for both regular and self-destruct)
        # Skip search - we already have all the data we need from record creation!
        logger.debug(f"Creating result object for newly created record: '{title}' ({record_uid})")
        
        from ..models import KeeperRecord
        newly_created_record = KeeperRecord(
            uid=record_uid,
                title=title,
            record_type='login',
            notes=notes or None
        )
        
        # Show only the newly created record (no unnecessary search)
        search_results = [newly_created_record]
        logger.debug("Optimized: Showing newly created record without search")
        
        # Build updated search modal with results, pre-selecting the new record
        from ..views import build_search_modal
        
        # Add the newly created UID to metadata so we can pre-select it
        metadata['newly_created_uid'] = record_uid
        metadata['newly_created_title'] = title
        
        logger.debug(f"Building search modal with query='{title}', results={len(search_results)}")
        updated_modal = build_search_modal(
            query=title,
            search_type=search_type,
            results=search_results,
            approval_data=metadata,
            loading=False
        )
        
        # Use the view_id we already retrieved
        if not view_id:
            logger.error("No previous_view_id found, cannot update search modal")
            # Send DM instead
            from ..utils import send_success_dm
            user_id = body["user"]["id"]
            send_success_dm(
                client, user_id,
                "Record Created",
                f"*Title:* {title}\n"
                f"*UID:* `{record_uid}`\n\n"
                f"Please use the search modal to find and approve access for <@{requester_id}>."
            )
            return
        
        # Update the search modal (pop back to it with updated content)
        logger.debug(f"Attempting to update view_id: {view_id}")
        try:
            response = client.views_update(
                view_id=view_id,
                view=updated_modal
            )
            logger.ok(f"Search modal updated successfully with query '{title}'")
            logger.debug(f"View update response: {response.get('ok', False)}")
        except Exception as e:
            logger.error(f"Failed to update search modal: {e}")
            import traceback
            traceback.print_exc()
            # Fallback: send DM with instructions
            from ..utils import send_success_dm
            user_id = body["user"]["id"]
            send_success_dm(
                client, user_id,
                "Record Created",
                f"*Title:* {title}\n"
                f"*UID:* `{record_uid}`\n\n"
                f"Please search for this record and approve access for <@{requester_id}>."
            )
        
    except Exception as e:
        logger.error(f"Error in create record flow: {e}")
        import traceback
        traceback.print_exc()
        
        # Send error DM
        from ..utils import send_error_dm
        user_id = body["user"]["id"]
        send_error_dm(
            client, user_id,
            "Error creating record",
            str(e)
        )


def handle_request_record_modal_submit(body: Dict[str, Any], client, config, keeper_client):
    """
    Handle request record modal submission.
    Creates an approval request for record access.
    """

    metadata = json.loads(body["view"]["private_metadata"])
    user_id = metadata["user_id"]
    user_name = metadata["user_name"]
    response_url = metadata.get("response_url", "")
    

    values = body["view"]["state"]["values"]
    identifier = (values.get("record_identifier", {}).get("identifier_input", {}).get("value") or "").strip()
    justification = (values.get("justification", {}).get("justification_input", {}).get("value") or "").strip()
    
    # Validate inputs
    if not identifier:
        return {
            "response_action": "errors",
            "errors": {"record_identifier": "Record UID or description is required"}
        }
    
    if not justification:
        return {
            "response_action": "errors",
            "errors": {"justification": "Justification is required"}
        }
    

    identifier, id_valid, id_error = sanitize_user_input(identifier, MAX_IDENTIFIER_LENGTH)
    if not id_valid:
        return {"response_action": "errors", "errors": {"record_identifier": id_error}}
    
    justification, just_valid, just_error = sanitize_user_input(justification, MAX_JUSTIFICATION_LENGTH)
    if not just_valid:
        return {"response_action": "errors", "errors": {"justification": just_error}}
    
    # Check if UID or description
    is_uid = is_valid_uid(identifier)
    

    record_details = None
    if is_uid:
        record_details = keeper_client.get_record_by_uid(identifier)
        if not record_details:
            return {"response_action": "errors", "errors": {"record_identifier": f"No record found with UID: {identifier}"}}
        
        # Validate it's actually a record, not a folder
        if record_details.record_type in ['folder', 'shared_folder', 'user_folder']:
            return {"response_action": "errors", "errors": {"record_identifier": "This is a folder. Please use /keeper-request-folder instead."}}
    
    # Generate approval ID and post request
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
        logger.info(f"Record access request {approval_id} submitted via modal by {user_id}")
        
        # Send ephemeral confirmation using response_url (same as respond() in slash commands)
        confirmation_text = (
            f"*Record access request submitted!*\n\n"
            f"Request ID: `{approval_id}`\n"
            f"Record: `{identifier}`\n"
            f"Justification: {justification}\n\n"
            f"Your request has been sent to <#{config.slack.approvals_channel_id}> for approval.\n"
            f"Once approved, please check your DM for details."
        )
        
        if response_url:
            _send_ephemeral_response(response_url, confirmation_text)
        
    except Exception as e:
        logger.error(f"Error posting record request from modal: {e}")
        return {"response_action": "errors", "errors": {"record_identifier": f"Failed to submit request: {str(e)}"}}
    
    return None


def handle_request_folder_modal_submit(body: Dict[str, Any], client, config, keeper_client):
    """
    Handle request folder modal submission.
    Creates an approval request for folder access.
    """

    metadata = json.loads(body["view"]["private_metadata"])
    user_id = metadata["user_id"]
    user_name = metadata["user_name"]
    response_url = metadata.get("response_url", "")
    

    values = body["view"]["state"]["values"]
    identifier = (values.get("folder_identifier", {}).get("identifier_input", {}).get("value") or "").strip()
    justification = (values.get("justification", {}).get("justification_input", {}).get("value") or "").strip()
    

    if not identifier:
        return {
            "response_action": "errors",
            "errors": {"folder_identifier": "Folder UID or description is required"}
        }
    
    if not justification:
        return {
            "response_action": "errors",
            "errors": {"justification": "Justification is required"}
        }
    
    # Sanitize inputs
    identifier, id_valid, id_error = sanitize_user_input(identifier, MAX_IDENTIFIER_LENGTH)
    if not id_valid:
        return {"response_action": "errors", "errors": {"folder_identifier": id_error}}
    
    justification, just_valid, just_error = sanitize_user_input(justification, MAX_JUSTIFICATION_LENGTH)
    if not just_valid:
        return {"response_action": "errors", "errors": {"justification": just_error}}
    
    # Check if UID or description
    is_uid = is_valid_uid(identifier)
    
    # Fetch folder details if UID
    folder_details = None
    if is_uid:
        folder_details = keeper_client.get_folder_by_uid(identifier)
        if not folder_details:
            return {"response_action": "errors", "errors": {"folder_identifier": f"No folder found with UID: {identifier}"}}
        
        # Validate it's actually a folder, not a record
        if folder_details.folder_type == 'record':
            return {"response_action": "errors", "errors": {"folder_identifier": "This is a record. Please use /keeper-request-record instead."}}
    
    # Generate approval ID and post request
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
            request_type=RequestType.FOLDER,
            justification=justification,
            duration="1h",
            folder_details=folder_details
        )
        logger.info(f"Folder access request {approval_id} submitted via modal by {user_id}")
        
        # Send ephemeral confirmation using response_url (same as respond() in slash commands)
        confirmation_text = (
            f"*Folder access request submitted!*\n\n"
            f"Request ID: `{approval_id}`\n"
            f"Folder: `{identifier}`\n"
            f"Justification: {justification}\n\n"
            f"Your request has been sent to <#{config.slack.approvals_channel_id}> for approval.\n"
            f"Once approved, please check your DM for details."
        )
        
        if response_url:
            _send_ephemeral_response(response_url, confirmation_text)
        
    except Exception as e:
        logger.error(f"Error posting folder request from modal: {e}")
        return {"response_action": "errors", "errors": {"folder_identifier": f"Failed to submit request: {str(e)}"}}
    
    return None


def handle_one_time_share_modal_submit(body: Dict[str, Any], client, config, keeper_client):
    """
    Handle one-time share modal submission.
    Creates an approval request for generating a one-time share link.
    """

    metadata = json.loads(body["view"]["private_metadata"])
    user_id = metadata["user_id"]
    user_name = metadata["user_name"]
    response_url = metadata.get("response_url", "")
    

    values = body["view"]["state"]["values"]
    identifier = (values.get("record_identifier", {}).get("identifier_input", {}).get("value") or "").strip()
    justification = (values.get("justification", {}).get("justification_input", {}).get("value") or "").strip()
    

    if not identifier:
        return {
            "response_action": "errors",
            "errors": {"record_identifier": "Record UID or description is required"}
        }
    
    if not justification:
        return {
            "response_action": "errors",
            "errors": {"justification": "Justification is required"}
        }
    

    identifier, id_valid, id_error = sanitize_user_input(identifier, MAX_IDENTIFIER_LENGTH)
    if not id_valid:
        return {"response_action": "errors", "errors": {"record_identifier": id_error}}
    
    justification, just_valid, just_error = sanitize_user_input(justification, MAX_JUSTIFICATION_LENGTH)
    if not just_valid:
        return {"response_action": "errors", "errors": {"justification": just_error}}
    
    # Check if UID or description
    is_uid = is_valid_uid(identifier)
    

    record_details = None
    if is_uid:
        record_details = keeper_client.get_record_by_uid(identifier)
        if not record_details:
            return {"response_action": "errors", "errors": {"record_identifier": f"No record found with UID: {identifier}"}}
        

        if record_details.record_type in ['folder', 'shared_folder', 'user_folder']:
            return {"response_action": "errors", "errors": {"record_identifier": "One-time share links can only be created for records, not folders."}}
    
    # Generate approval ID and post request
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
            request_type=RequestType.ONE_TIME_SHARE,
            justification=justification,
            duration="1h",
            record_details=record_details
        )
        logger.info(f"One-time share request {approval_id} submitted via modal by {user_id}")
        
        # Send ephemeral confirmation using response_url (same as respond() in slash commands)
        confirmation_text = (
            f"*One-Time Share request submitted!*\n\n"
            f"Request ID: `{approval_id}`\n"
            f"Record: `{identifier}`\n"
            f"Justification: {justification}\n\n"
            f"Your request has been sent to <#{config.slack.approvals_channel_id}> for approval.\n"
            f"Once approved, the one-time share link will be sent to you via DM."
        )
        
        if response_url:
            _send_ephemeral_response(response_url, confirmation_text)
        
    except Exception as e:
        logger.error(f"Error posting one-time share request from modal: {e}")
        return {"response_action": "errors", "errors": {"record_identifier": f"Failed to submit request: {str(e)}"}}
    
    return None
