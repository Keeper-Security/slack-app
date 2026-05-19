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
from ..models import PermissionLevel, KDPermissionRole, RequestType
from ..views import decode_search_item_value
from ..views import update_approval_message, send_access_granted_dm, post_approval_request
from ..utils import (
    parse_duration_to_seconds, format_duration, format_permission_name,
    get_user_email_from_slack,
    generate_approval_id, is_valid_uid, sanitize_user_input,
    MAX_JUSTIFICATION_LENGTH, MAX_IDENTIFIER_LENGTH,
    is_record_owner_error, is_permission_conflict_error
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
    request_type = approval_data.get("type", approval_data.get("search_type", "record"))
    
    # Extract values from form
    values = body["view"]["state"]["values"]
    
    # Check if user modified search query
    new_query = values.get("search_query", {}).get("update_search_query", {}).get("value", "").strip()
    search_type = approval_data.get("search_type", request_type)
    
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

        # Drop any prior selection when running a new search
        approval_data.pop("selected_uid", None)
        approval_data.pop("selected_is_keeper_drive", None)
        
        # Run search
        request_type = approval_data.get("type", "record")
        exclude_pam = request_type == "one_time_share"
        if search_type == "record":
            results = keeper_client.search_records(
                new_query, limit=20, exclude_pam=exclude_pam
            )
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
    
    # KD's universal deferred-ack pattern handles both PAM rotate-on-expire
    # and Keeper Drive flows: we always ack with a "Processing..." view (see
    # build_approval_processing_modal below) so the modal stays open past
    # Slack's 3-second window and we can swap it via views_update with the
    # final success/error/retry view once the backend call returns.
    selected_uid, is_keeper_drive = decode_search_item_value(selected_item["value"])
    
    # Get record title from the selected item or metadata
    record_title = selected_item.get("text", {}).get("text", "").split(" (")[0] if selected_item else f"Record {selected_uid}"
    if not record_title or record_title.startswith("Record "):
        record_title = approval_data.get('newly_created_title', approval_data.get('record_title', f"Record {selected_uid}"))
    
    approval_id = approval_data["approval_id"]
    from ..views import (
        build_approval_processing_modal,
        build_approval_success_modal,
        build_approval_error_modal,
    )

    ack(response_action="update", view=build_approval_processing_modal(
        approval_id=approval_id,
        item_title=record_title,
        request_type=request_type,
    ))
    view_id = body["view"]["id"]

    def _show_modal_result(view: Dict[str, Any]) -> None:
        try:
            client.views_update(view_id=view_id, view=view)
        except Exception as update_err:
            logger.error(f"Failed to update approval modal: {update_err}")
    
    # Check if this is a self-destruct record
    is_self_destruct = approval_data.get('create_self_destruct', False)
    permission_display = PermissionLevel.VIEW_ONLY.value
    # Extract permission and duration
    if is_self_destruct:
        # Self-destruct records: use duration from creation, always view-only
        logger.info("Self-destruct record detected - sharing with view-only access")
        permission = PermissionLevel.VIEW_ONLY
        permission_display = PermissionLevel.VIEW_ONLY.value
        self_destruct_duration_str = approval_data.get('self_destruct_duration', '1h')
        duration_seconds = parse_duration_to_seconds(self_destruct_duration_str)
        duration_value = self_destruct_duration_str
        duration_text = format_duration(self_destruct_duration_str)
        editable = False
    else:
        # Normal records: use admin-selected permission and duration
        permission_state = (
            values.get("permission_selector_kd")
            or values.get("permission_selector_classic")
            or values.get("permission_selector", {})
        )
        permission_block = permission_state.get("select_permission", {})
        if is_keeper_drive:
            default_permission = "viewer"
        elif request_type == "folder":
            default_permission = PermissionLevel.NO_PERMISSIONS.value
        else:
            default_permission = PermissionLevel.VIEW_ONLY.value
        permission_value = permission_block.get("selected_option", {}).get("value", default_permission)
        permission = None
        kd_role = None

        if is_keeper_drive and request_type in ("record", "folder"):
            kd_role = KDPermissionRole(permission_value)
            permission_display = permission_value  # human-readable via format_permission_name in UI
        else:
            permission = PermissionLevel(permission_value)
            permission_display = permission_value
        
        # For one-time shares, convert permission to editable flag
        editable = (permission_value == PermissionLevel.CAN_EDIT.value)
        
        # Some permissions are always permanent (no duration)
        if is_keeper_drive and request_type in ("record", "folder"):
            PERMANENT_ONLY_PERMISSIONS = [KDPermissionRole.TRANSFER_OWNER.value]
        else:
            PERMANENT_ONLY_PERMISSIONS = [
                PermissionLevel.CAN_SHARE.value,
                PermissionLevel.EDIT_AND_SHARE.value,
                PermissionLevel.CHANGE_OWNER.value,
                PermissionLevel.MANAGE_USERS.value,
                PermissionLevel.MANAGE_ALL.value,
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
    
    requester_id = approval_data["requester_id"]
    user_email = get_user_email_from_slack(client, requester_id)

    rotate_on_expire = False
    if (
        request_type == "record"
        and duration_seconds
        and not is_self_destruct
        and values.get("pam_rotate_block")
    ):
        from ..utils import (
            extract_rotate_on_expire_from_modal,
            is_pam_user_record_type,
        )
        record_for_rotate = keeper_client.get_record_by_uid(selected_uid)
        if record_for_rotate and is_pam_user_record_type(record_for_rotate.record_type):
            rotate_on_expire = extract_rotate_on_expire_from_modal(values)
    
    try:
        if request_type == "record":
            if is_keeper_drive:
                result = keeper_client.grant_kd_record_access(
                    record_uid=selected_uid,
                    user_email=user_email,
                    role=kd_role,
                    duration_seconds=duration_seconds,
                )
            else:
                result = keeper_client.grant_record_access(
                    record_uid=selected_uid,
                    user_email=user_email,
                    permission=permission,
                    duration_seconds=duration_seconds,
                    rotate_on_expire=rotate_on_expire,
                )
        elif request_type == "folder":
            if is_keeper_drive:
                result = keeper_client.grant_kd_folder_access(
                    folder_uid=selected_uid,
                    user_email=user_email,
                    role=kd_role,
                    duration_seconds=duration_seconds,
                )
            else:
                result = keeper_client.grant_folder_access(
                    folder_uid=selected_uid,
                    user_email=user_email,
                    permission=permission,
                    duration_seconds=duration_seconds,
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
            from ..views import send_share_link_dm
            from ..utils import handle_invitation_sent
            
            # Check if this was an invitation (user not in vault)
            if result.get('invitation_sent'):
                message_ts = approval_data.get("message_ts")
                channel_id = approval_data.get("channel_id", config.slack.approvals_channel_id)
                
                handle_invitation_sent(
                    client=client,
                    channel_id=channel_id,
                    message_ts=message_ts,
                    approver_id=approver_id,
                    requester_id=requester_id,
                    request_type=request_type,
                    identifier=selected_uid,
                    permission_value=permission_display,
                    approval_id=approval_id
                )
                _show_modal_result(build_approval_success_modal(
                    approval_id=approval_id,
                    item_title=record_title,
                    request_type=request_type,
                    permission_display=permission_display,
                    expires_at=result.get('expires_at', 'Pending Invitation'),
                    invitation_sent=True,
                ))
                return
            
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
                # Generate deep link based on request type
                from ..views import _get_vault_deep_link
                deep_link = _get_vault_deep_link(request_type, selected_uid, keeper_client.server_domain)
                item_label = "Record" if request_type == "record" else "Folder"
                access_message = f"*Access Granted!*\n\n" \
                                f"*Request ID:* `{approval_id}`\n" \
                                f"*{item_label}:* {record_title}\n" \
                                f"*{item_label} Link:* <{deep_link}|Open in Vault>\n" \
                                f"*Permission:* {format_permission_name(permission_display)}\n" \
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
                        uid_label = "Record UID"
                    else:
                        if is_permanent:
                            status_msg = "*Access Granted (No Expiration)*\nAccess remains active indefinitely"
                        else:
                            status_msg = f"*Temporary Access Granted*\nAccess will expire on *{expires_at}*"
                        if result.get('rotate_on_expire'):
                            status_msg += "\n*PAM credentials will rotate* when access expires"
                        
                        # Add self-destruct note if applicable
                        if is_self_destruct:
                            status_msg += f"\n\n*Self-Destruct Record*\nRecord will auto-delete after {duration_text}"
                            approval_text = "Self-Destruct Record Access Approved"
                            uid_label = "Record UID"
                        else:
                            # Set approval text and UID label based on request type
                            if request_type == "record":
                                approval_text = "Record Access Request Approved"
                                uid_label = "Record UID"
                            elif request_type == "folder":
                                approval_text = "Folder Access Request Approved"
                                uid_label = "Folder UID"
                    
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
                                    "text": f"*{uid_label}:* `{selected_uid}`\n"
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

            _show_modal_result(build_approval_success_modal(
                approval_id=approval_id,
                item_title=record_title,
                request_type=request_type,
                permission_display=permission_display,
                expires_at=result.get('expires_at', duration_text),
                rotate_on_expire=bool(result.get('rotate_on_expire')),
            ))
            logger.info(f"Access granted successfully for {approval_id}")
        else:
            # Failed to grant access
            error_msg = result.get('error', 'Unknown error')
            error_code = result.get('error_code')
            logger.error(f"Failed to grant access: {error_msg}")

            # PAM rotation not configured: keep modal experience, show retry view
            # with banner + preserved state so the admin can uncheck rotation
            # and re-submit without leaving the modal.
            if error_code == 'pam_rotation_not_configured':
                from ..views import build_search_modal
                cached_results = approval_data.get('cached_results', [])
                retry_approval_data = dict(approval_data)
                retry_approval_data['selected_uid'] = selected_uid
                retry_approval_data['selected_is_keeper_drive'] = is_keeper_drive
                if permission is not None:
                    retry_approval_data['selected_permission'] = permission.value
                if duration_seconds and duration_value not in (None, 'permanent'):
                    retry_approval_data['selected_duration'] = duration_value
                retry_approval_data['rotate_initial_checked'] = False
                retry_modal = build_search_modal(
                    query=approval_data.get('query', ''),
                    search_type=approval_data.get('search_type', 'record'),
                    results=cached_results,
                    approval_data=retry_approval_data,
                    loading=False,
                    error_banner=(
                        "Rotation is not configured on this PAM User record. "
                        "Configure rotation in the Keeper Vault, or keep "
                        "*Rotate credentials when access expires* unchecked and approve again."
                    ),
                )
                _show_modal_result(retry_modal)
                logger.info(
                    f"Approval {approval_id}: showed search modal with "
                    "rotation-not-configured banner via views_update"
                )
                return
            
            _show_modal_result(build_approval_error_modal(
                approval_id=approval_id,
                item_title=record_title,
                error_msg=error_msg,
                request_type=request_type,
            ))

            # Check if user is the record owner
            if is_record_owner_error(error_msg):
                logger.info(f"User is record owner for approval {approval_id}, sending DM to approver")
                from ..utils import send_error_dm
                send_error_dm(
                    client=client,
                    user_id=approver_id,
                    title="Access grant failed:",
                    message=f"The selected user is the current owner of this {request_type} and already has full permissions.\n\n"
                            f"*Request ID:* `{approval_id}`\n"
                            f"*{request_type.capitalize()}:* {record_title}"
                )
                if "channel_id" in approval_data and "message_ts" in approval_data:
                    try:
                        from ..views import update_approval_message
                        update_approval_message(
                            client=client,
                            channel_id=approval_data["channel_id"],
                            message_ts=approval_data["message_ts"],
                            status="User Already Has Full Access (Owner)",
                            original_blocks=[]
                        )
                    except Exception as update_error:
                        logger.debug(f"Could not update approval card: {update_error}")
            elif is_permission_conflict_error(error_msg):
                logger.info(f"Permission conflict detected for approval {approval_id}, sending DM to approver")
                from ..utils import send_error_dm
                send_error_dm(
                    client=client,
                    user_id=approver_id,
                    title="Cannot Grant Access - Permission Conflict",
                    message=f"{error_msg}\n\n"
                            f"*Request ID:* `{approval_id}`\n"
                            f"*{request_type.capitalize()}:* {record_title}\n\n"
                            f"The approval request remains active in the channel. Please revoke the user's existing access first, "
                            f"then try approving again from the approval channel."
                )
            else:
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
                # Note: the in-modal error view was already shown above via
                # _show_modal_result(build_approval_error_modal(...)).
            
    except Exception as e:
        logger.error(f"Error granting access from search modal: {e}")
        import traceback
        traceback.print_exc()

        # Replace the still-open processing modal with an error view so the
        # admin is not stuck looking at "Processing...".
        try:
            _show_modal_result(build_approval_error_modal(
                approval_id=approval_id,
                item_title=record_title,
                error_msg=f"An error occurred while processing your approval: {str(e)}",
                request_type=request_type,
            ))
        except Exception as inner_modal_error:
            logger.warning(
                f"Could not update modal after unexpected error: {inner_modal_error}"
            )
        # Also DM the approver as a durable fallback.
        from ..utils import send_error_dm
        send_error_dm(
            client, body["user"]["id"],
            "System Error",
            f"An error occurred while processing your approval: {str(e)}"
        )

def handle_item_selection_action(body: Dict[str, Any], client, config, keeper_client):
    """
    Handle record/folder radio selection in the search modal.

    Refreshes the modal so that:
    - Permission options reflect Classic vs Keeper Drive context, and
    - The PAM rotate-on-expiration checkbox appears only when a `pamUser`
      record is selected.
    """
    try:
        selected = body["actions"][0].get("selected_option")
        if not selected:
            return

        selected_uid, is_keeper_drive = decode_search_item_value(selected["value"])
        view = body["view"]
        metadata = json.loads(view["private_metadata"])
        metadata["selected_uid"] = selected_uid
        metadata["selected_is_keeper_drive"] = is_keeper_drive

        from ..views import build_search_modal

        updated_modal = build_search_modal(
            query=metadata.get("query", ""),
            search_type=metadata.get("search_type", "record"),
            results=metadata.get("cached_results", []),
            approval_data=metadata,
            selected_is_keeper_drive=is_keeper_drive,
        )

        client.views_update(view_id=view["id"], view=updated_modal)
        logger.info(
            f"Search modal updated for selection uid={selected_uid}, keeper_drive={is_keeper_drive}"
        )
    except Exception as exc:
        logger.error(f"item_selection handler error: {exc}")




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

    # Drop any prior selection when running a new search
    approval_data.pop("selected_uid", None)
    approval_data.pop("selected_is_keeper_drive", None)
    
    # Re-run search
    request_type = approval_data.get("type", "record")
    exclude_pam = request_type == "one_time_share"
    if search_type == "record":
        results = keeper_client.search_records(
            new_query, limit=20, exclude_pam=exclude_pam
        )
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


def _is_classic_vault_checked(values: Dict[str, Any]) -> bool:
    """True if Classic vault checkbox is selected in create-record modal."""
    selected = values.get("classic_vault", {}).get("classic_vault_checkbox", {}).get("selected_options", [])
    return any(opt.get("value") == "classic" for opt in selected)


def handle_create_new_record_action(body: Dict[str, Any], client, config, keeper_client):
    """
    Handle 'Create New Record' button click in search modal.
    Opens the record creation form (Classic checkbox selects record-add vs kd-record-add).
    """
    from ..views import build_create_record_modal

    value = body["actions"][0].get("value", "{}")
    approval_data = json.loads(value)

    view_state = body.get("view", {}).get("state", {}).get("values", {})
    current_query = view_state.get("search_query", {}).get("update_search_query", {}).get("value", "")

    try:
        client.views_push(
            trigger_id=body["trigger_id"],
            view=build_create_record_modal(
                approval_data,
                current_query,
                show_expiration=False,
                use_classic=False,
            ),
        )
    except Exception as e:
        logger.error(f"Failed to open create record modal: {e}", exc_info=True)


def handle_create_record_classic_vault_action(body: Dict[str, Any], client):
    """Toggle Classic vs Keeper Drive options when the vault checkbox changes."""
    view = body["view"]
    metadata = json.loads(view["private_metadata"])
    values = view.get("state", {}).get("values", {})

    use_classic = _is_classic_vault_checked(values)
    self_destruct_opts = values.get("self_destructive_actions", {}).get(
        "self_destructive_checkbox", {}
    ).get("selected_options", [])
    show_expiration = use_classic and len(self_destruct_opts) > 0

    title = values.get("record_title", {}).get("title_input", {}).get("value", "")

    from ..views import build_create_record_modal
    client.views_update(
        view_id=view["id"],
        view=build_create_record_modal(
            approval_data=metadata,
            original_query=title or "",
            show_expiration=show_expiration,
            use_classic=use_classic,
        ),
    )


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
    
    auto_gen_selected = values.get("auto_gen_password", {}).get("auto_gen_checkbox", {}).get("selected_options", [])
    auto_gen_checked = any(opt.get("value") == "auto_gen" for opt in auto_gen_selected)
    
    use_classic = _is_classic_vault_checked(values)
    is_keeper_drive = not use_classic

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
        return {
            "response_action": "errors",
            "errors": {
                "record_title": "Title is required"
            }
        }
    
    if auto_gen_checked and password and password.upper() != '$GEN':
        return {
            "response_action": "errors",
            "errors": {
                "record_password": "Please either enter a password or check auto-generate, not both."
            }
        }
    
    if is_keeper_drive and self_destruct_enabled:
        from ..utils import send_error_dm
        send_error_dm(
            client, body["user"]["id"],
            "Self-destruct not supported",
            "Self-destruct records are only supported in Classic shared folders.",
        )
        return

    try:
        vault_label = "Classic" if use_classic else "Keeper Drive"
        logger.info(
            f"Creating {vault_label} record '{title}' for requester {requester_id}"
            + (f" with self-destruct" if self_destruct_enabled else "")
        )
        generate_password = auto_gen_checked or (password.upper() == '$GEN' if password else False)

        if is_keeper_drive:
            create_result = keeper_client.create_kd_record(
                title=title,
                login=login or None,
                password=None if generate_password else (password or None),
                url=url or None,
                notes=notes or None,
                generate_password=generate_password,
            )
        else:
            create_result = keeper_client.create_record(
                title=title,
                login=login or None,
                password=None if generate_password else (password or None),
                url=url or None,
                notes=notes or None,
                generate_password=generate_password,
                self_destruct_duration=self_destruct_duration if self_destruct_enabled else None,
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
            notes=notes or None,
            is_keeper_drive=is_keeper_drive or create_result.get('is_keeper_drive', False),
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
