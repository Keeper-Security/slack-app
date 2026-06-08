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
from typing import Any, Dict, Optional
from ..models import PermissionLevel, RequestType
from ..views import update_approval_message, send_access_granted_dm, post_approval_request
from ..commander_errors import COMMAND_NOT_ALLOWED, COMMANDER_UNAUTHORIZED
from ..utils import (
    parse_duration_to_seconds, format_duration, get_user_email_from_slack,
    generate_approval_id, is_valid_uid, sanitize_user_input,
    MAX_JUSTIFICATION_LENGTH, MAX_IDENTIFIER_LENGTH,
    is_record_owner_error, is_permission_conflict_error,
    format_approval_audit_log
)
from ..logger import logger


_COMMANDER_REJECTED_CODES = (COMMAND_NOT_ALLOWED, COMMANDER_UNAUTHORIZED)


def _maybe_commander_search_error_banner(
    client,
    user_id: str,
    search_error: Optional[Dict[str, Any]],
    query: str,
    search_type: str,
) -> str:
    """
    If Commander rejected the search/sync (HTTP 401/403), DM the user with
    the admin-facing guidance and return a banner string ready to be passed
    as ``error_banner`` to ``build_search_modal``. Returns an empty string
    for any other / no error so the caller can skip the banner block.
    """
    if not search_error:
        return ""
    if search_error.get("error_code") not in _COMMANDER_REJECTED_CODES:
        return ""

    from ..utils import notify_commander_unauthorized_or_forbidden

    return notify_commander_unauthorized_or_forbidden(
        client=client,
        user_id=user_id,
        error=search_error,
        context_lines=[
            f"*Search type:* {search_type}",
            f"*Search query:* `{query}`",
        ],
    )


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


def handle_item_selection_action(body: Dict[str, Any], client, config, keeper_client) -> None:
    """
    Refresh the search modal when the user selects a result so the PAM rotate
    checkbox can appear only for PAM records.
    """
    try:
        view = body.get("view") or {}
        view_id = view.get("id")
        if not view_id:
            return

        metadata_raw = view.get("private_metadata", "{}")
        try:
            metadata = json.loads(metadata_raw)
        except json.JSONDecodeError:
            logger.warning("item_selection: could not parse private_metadata")
            return

        selected_option = body.get("actions", [{}])[0].get("selected_option") or {}
        raw_value = selected_option.get("value")
        if not raw_value:
            return

        from ..views import decode_search_item_value, build_search_modal

        selected_uid, selected_is_nsf = decode_search_item_value(raw_value)
        if not selected_uid:
            return

        previous_uid = metadata.get("selected_uid")
        previous_was_nsf = bool(metadata.get("selected_item_is_nsf", False))

        if selected_is_nsf != previous_was_nsf:
            metadata.pop("selected_permission", None)

        metadata["selected_uid"] = selected_uid
        metadata["selected_item_is_nsf"] = selected_is_nsf

        search_type = metadata.get("search_type", "record")
        pam_folder_error: Optional[Dict[str, Any]] = None
        if search_type == "folder" and not selected_is_nsf:
            # NSF folders never need the PAM rotate-on-expire probe; skip the
            # list-sf call entirely for them.
            if selected_uid != previous_uid:
                try:
                    is_pam_folder, pam_folder_error = (
                        keeper_client.is_pam_user_folder(selected_uid)
                    )
                    metadata["selected_folder_is_pam_user"] = is_pam_folder
                except Exception as e:
                    logger.warning(
                        f"item_selection: is_pam_user_folder({selected_uid}) "
                        f"failed; falling back to non-PAM: {e}"
                    )
                    metadata["selected_folder_is_pam_user"] = False
                    pam_folder_error = None
        elif selected_is_nsf:
            metadata["selected_folder_is_pam_user"] = False

        pam_folder_banner = _maybe_commander_search_error_banner(
            client=client,
            user_id=body.get("user", {}).get("id", ""),
            search_error=pam_folder_error,
            query=metadata.get("query", ""),
            search_type=search_type,
        )

        updated_modal = build_search_modal(
            query=metadata.get("query", ""),
            search_type=search_type,
            results=metadata.get("cached_results", []),
            approval_data=metadata,
            loading=False,
            error_banner=pam_folder_banner or None,
        )

        client.views_update(view_id=view_id, view=updated_modal)
        logger.debug(
            f"item_selection: refreshed modal for selected_uid={selected_uid} "
            f"is_nsf={selected_is_nsf}"
        )
    except Exception as exc:
        logger.error(f"item_selection handler error: {exc}")


def handle_create_record_classic_vault_action(
    body: Dict[str, Any], client, config, keeper_client
) -> None:
    try:
        view = body.get("view") or {}
        view_id = view.get("id")
        if not view_id:
            return

        metadata_raw = view.get("private_metadata", "{}")
        try:
            approval_data = json.loads(metadata_raw)
        except json.JSONDecodeError:
            logger.warning("classic_vault: could not parse private_metadata")
            return

        action = body.get("actions", [{}])[0]
        selected_options = action.get("selected_options", []) or []
        use_classic = any(opt.get("value") == "classic" for opt in selected_options)

        approval_data["use_classic"] = use_classic

        # Preserve the self-destruct selection across the rebuild.
        state_values = view.get("state", {}).get("values", {})
        sd_selected = (
            state_values.get("self_destructive_actions", {})
            .get("self_destructive_checkbox", {})
            .get("selected_options", [])
        )
        show_expiration = use_classic and bool(sd_selected)

        from ..views import build_create_record_modal

        updated_modal = build_create_record_modal(
            approval_data=approval_data,
            original_query=approval_data.get("query", ""),
            show_expiration=show_expiration,
            use_classic=use_classic,
        )
        client.views_update(view_id=view_id, view=updated_modal)
        logger.debug(f"classic_vault toggle: use_classic={use_classic}")
    except Exception as exc:
        logger.error(f"classic_vault handler error: {exc}")


def _is_classic_vault_checked(state_values: Dict[str, Any]) -> bool:
    try:
        selected = (
            state_values.get("classic_vault", {})
            .get("classic_vault_checkbox", {})
            .get("selected_options", [])
        )
        return any(opt.get("value") == "classic" for opt in selected)
    except Exception:
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

    # Defense-in-depth self-approval guard: if a requester somehow opened the modal for their own request, refuse to grant access.
    approver_id = body.get("user", {}).get("id")
    requester_id = approval_data.get("requester_id")
    if has_results and approver_id and requester_id and approver_id == requester_id:
        try:
            ack(
                response_action="update",
                view={
                    "type": "modal",
                    "title": {"type": "plain_text", "text": "Cannot Self-Approve"},
                    "close": {"type": "plain_text", "text": "Close"},
                    "blocks": [{
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": (
                                ":no_entry_sign: *You cannot approve your own request.*\n\n"
                                "Please ask your admin or another team member "
                                "to review and approve it on your behalf."
                            ),
                        },
                    }],
                },
            )
        except Exception as e:
            logger.warning(f"Could not surface self-approval error in modal: {e}")
        logger.info(
            f"Blocked self-approval via search modal: approver_id={approver_id} "
            f"== requester_id={requester_id}"
        )
        return
    
    if not has_results:
        # No results yet - user is searching
        logger.debug(f"No results block - running search with query: '{new_query}'")
        
        # Acknowledge immediately for search operations
        ack()

        # Drop any prior selection (and its derived PAM-folder cache) when
        # running a new search so the next render starts clean.
        approval_data.pop("selected_uid", None)
        approval_data.pop("selected_folder_is_pam_user", None)
        
        # Run search. ``for_one_time_share`` filters out PAM + NSF records
        # for OTS requests (Commander's ``one-time-share`` supports neither).
        request_type = approval_data.get("type", "record")
        for_one_time_share = request_type == "one_time_share"
        if search_type == "record":
            results, search_error = keeper_client.search_records(
                new_query, limit=20, for_one_time_share=for_one_time_share
            )
        else:
            results, search_error = keeper_client.search_folders(new_query, limit=20)

        search_banner = _maybe_commander_search_error_banner(
            client=client,
            user_id=body.get("user", {}).get("id", ""),
            search_error=search_error,
            query=new_query,
            search_type=search_type,
        )

        # Rebuild and update modal with results using API call
        from ..views import build_search_modal
        updated_modal = build_search_modal(
            query=new_query,
            search_type=search_type,
            results=results,
            approval_data=approval_data,
            error_banner=search_banner or None,
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

    # Validate the NSF permission BEFORE acking.
    from ..views import decode_search_item_value as _decode_selected_value
    from ..models import NSFPermissionRole as _NSFRoleForValidation
    _pre_selected_uid, _pre_selected_is_nsf = _decode_selected_value(
        selected_item["value"]
    )
    if _pre_selected_is_nsf and not approval_data.get("create_self_destruct", False):
        _pre_permission_value = (
            values.get("permission_selector", {})
            .get("select_permission", {})
            .get("selected_option", {})
            .get("value", "")
        )
        try:
            _NSFRoleForValidation(_pre_permission_value)
        except ValueError:
            logger.warning(
                f"Rejected NSF grant: invalid permission value "
                f"{_pre_permission_value!r} for uid={_pre_selected_uid}"
            )
            ack(response_action="errors", errors={
                "permission_selector": (
                    "Please re-select a Nested Share Folder permission "
                    "before approving."
                )
            })
            return

    # Item selected - acknowledge IMMEDIATELY (Slack requires ack within 3 seconds).
    pre_ack_request_type = approval_data.get("type", "record")
    pre_ack_is_self_destruct = approval_data.get("create_self_destruct", False)

    defer_ack = (
        pre_ack_request_type in ("record", "folder")
        and not pre_ack_is_self_destruct
    )
    submitted_view_id = body["view"]["id"]

    if defer_ack:
        from ..views import build_grant_processing_modal
        ack(
            response_action="update",
            view=build_grant_processing_modal(),
        )
        logger.debug(
            f"Deferred ack with processing modal for {pre_ack_request_type} "
            f"share (sync-down + share command in flight); "
            f"view_id={submitted_view_id}"
        )
    else:
        ack()


    from ..views import decode_search_item_value
    from ..models import NSFPermissionRole
    raw_selected_value = selected_item["value"]
    selected_uid, selected_is_nsf = decode_search_item_value(raw_selected_value)
    
    # Get record title from the selected item or metadata
    record_title = selected_item.get("text", {}).get("text", "").split(" (")[0] if selected_item else f"Record {selected_uid}"
    # Strip the [NSF] / [Classic] badge we prepend in build_search_modal so
    # downstream messaging shows just the human title.
    for badge in ("[NSF] ", "[Classic] "):
        if record_title.startswith(badge):
            record_title = record_title[len(badge):]
            break
    if not record_title or record_title.startswith("Record "):
        record_title = approval_data.get('newly_created_title', approval_data.get('record_title', f"Record {selected_uid}"))
    
    # Check if this is a self-destruct record
    is_self_destruct = approval_data.get('create_self_destruct', False)

    permission = None
    permission_label = None
    nsf_role: Optional[NSFPermissionRole] = None
    
    # Extract permission and duration
    if is_self_destruct:
        # Self-destruct records: use duration from creation, always view-only.
        # (Self-destruct is Classic-only, so NSF path can't reach here.)
        logger.info("Self-destruct record detected - sharing with view-only access")
        permission = PermissionLevel.VIEW_ONLY
        permission_label = PermissionLevel.VIEW_ONLY.value
        self_destruct_duration_str = approval_data.get('self_destruct_duration', '5m')
        duration_seconds = parse_duration_to_seconds(self_destruct_duration_str)
        duration_value = self_destruct_duration_str
        duration_text = format_duration(self_destruct_duration_str)
        editable = False
    else:
        # Normal records: use admin-selected permission and duration
        permission_block = values.get("permission_selector", {}).get("select_permission", {})
        permission_value = permission_block.get("selected_option", {}).get("value", "view_only")

        # For one-time shares, convert permission to editable flag (only
        # makes sense on the Classic path; NSF doesn't do one-time shares).
        editable = (permission_value == PermissionLevel.CAN_EDIT.value)

        if selected_is_nsf:
            try:
                nsf_role = NSFPermissionRole(permission_value)
            except ValueError:
                # Defensive backstop only: invalid NSF permission values are
                # rejected with an inline modal error before the ack (see the
                # pre-ack validation above), so this branch should be
                # unreachable in normal flow. Kept to avoid an unhandled
                # exception after the deferred ack if state ever slips through.
                nsf_role = NSFPermissionRole.VIEWER
            permission_label = nsf_role.value
            permission = nsf_role

            # Transfer-ownership is always permanent.
            if nsf_role == NSFPermissionRole.TRANSFER_OWNER:
                duration_seconds = None
                duration_value = "permanent"
                duration_text = "No Expiration"
            else:
                duration_block = values.get("grant_duration", {}).get("grant_duration_select", {})
                selected_option = duration_block.get("selected_option") or {}
                duration_value = selected_option.get("value")
                if duration_value == "permanent" or not duration_value:
                    duration_seconds = None
                    duration_value = "permanent"
                    duration_text = "No Expiration"
                else:
                    duration_seconds = parse_duration_to_seconds(duration_value)
                    duration_text = format_duration(duration_value)
        else:
            permission = PermissionLevel(permission_value)
            permission_label = permission.value

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
    approver_email = get_user_email_from_slack(client, approver_id)

    rotate_on_expire = False
    is_pam_target = False
    # NSF items can never be PAM (they live in Nested Share Folder, not PAM rotation
    # configs), so the entire rotate-on-expire probe is skipped for them.
    if (
        duration_seconds
        and not is_self_destruct
        and not selected_is_nsf
        and values.get("pam_rotate_block")
    ):
        from ..utils import (
            extract_rotate_on_expire_from_modal,
            is_pam_user_record_type,
        )
        if request_type == "record":
            record_for_rotate = keeper_client.get_record_by_uid(selected_uid)
            if record_for_rotate and is_pam_user_record_type(record_for_rotate.record_type):
                is_pam_target = True
                rotate_on_expire = extract_rotate_on_expire_from_modal(values)
        elif request_type == "folder":
            cached_is_pam_folder = approval_data.get("selected_folder_is_pam_user")
            if cached_is_pam_folder is None:
                try:
                    cached_is_pam_folder, _ = (
                        keeper_client.is_pam_user_folder(selected_uid)
                    )
                except Exception as e:
                    logger.warning(
                        f"is_pam_user_folder re-check failed for {selected_uid}: {e}"
                    )
                    cached_is_pam_folder = False
            if cached_is_pam_folder:
                is_pam_target = True
                rotate_on_expire = extract_rotate_on_expire_from_modal(values)
    
    try:
        if selected_is_nsf and request_type == "record":
            result = keeper_client.grant_nsf_record_access(
                record_uid=selected_uid,
                user_email=user_email,
                role=nsf_role,
                duration_seconds=duration_seconds,
            )
        elif selected_is_nsf and request_type == "folder":
            result = keeper_client.grant_nsf_folder_access(
                folder_uid=selected_uid,
                user_email=user_email,
                role=nsf_role,
                duration_seconds=duration_seconds,
            )
        elif request_type == "record":
            result = keeper_client.grant_record_access(
                record_uid=selected_uid,
                user_email=user_email,
                permission=permission,
                duration_seconds=duration_seconds,
                rotate_on_expire=rotate_on_expire,
            )
        elif request_type == "folder":
            result = keeper_client.grant_folder_access(
                folder_uid=selected_uid,
                user_email=user_email,
                permission=permission,
                duration_seconds=duration_seconds,
                rotate_on_expire=rotate_on_expire,
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
                    permission_value=permission.value,
                    approval_id=approval_id
                )
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
                logger.info(format_approval_audit_log(
                    approval_id=approval_id,
                    request_type=request_type,
                    identifier=selected_uid,
                    requester_email=user_email,
                    approver_email=approver_email,
                    permission=permission.value,
                    duration_text=duration_text,
                ))
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
                                f"*Permission:* {permission.value}\n" \
                                f"*Expires:* {result.get('expires_at', duration_text)}"
                
                # Add self-destruct notice if applicable
                if is_self_destruct:
                    access_message += f"\n\n*Self-Destruct Record*\n" \
                                    f"This record will automatically delete from the vault after {duration_text}."
                
                from ..utils import send_dm
                send_dm(client, requester_id, access_message)
                logger.info(format_approval_audit_log(
                    approval_id=approval_id,
                    request_type=request_type,
                    identifier=selected_uid,
                    requester_email=user_email,
                    approver_email=approver_email,
                    permission=permission.value,
                    duration_text=duration_text,
                    rotate_on_expire=bool(result.get('rotate_on_expire')),
                    is_pam=is_pam_target,
                ))
            
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

            # If we deferred the ack, the modal is still open showing
            if defer_ack:
                try:
                    from ..views import build_grant_success_modal
                    success_title = "Access granted successfully"
                    detail_lines = [
                        f"*Request ID:* `{approval_id}`",
                        f"*Record:* {record_title}",
                        f"*Permission:* {permission.value}",
                        f"*Expires:* {result.get('expires_at', duration_text)}",
                    ]
                    if result.get('rotate_on_expire'):
                        detail_lines.append(
                            ":arrows_counterclockwise: *PAM credentials will rotate when access expires.*"
                        )
                    client.views_update(
                        view_id=submitted_view_id,
                        view=build_grant_success_modal(
                            title_text=success_title,
                            detail_lines=detail_lines,
                        ),
                    )
                except Exception as update_error:
                    logger.warning(
                        f"Failed to update modal with success view: {update_error}"
                    )

            logger.info(f"Access granted successfully for {approval_id}")
        else:
            # Failed to grant access
            error_msg = result.get('error', 'Unknown error')
            error_code = result.get('error_code')
            logger.error(f"Failed to grant access: {error_msg}")

            # PAM rotation not configured: keep modal experience, reopen with banner + state
            if error_code == 'pam_rotation_not_configured':
                from ..views import build_search_modal
                cached_results = approval_data.get('cached_results', [])
                retry_approval_data = dict(approval_data)
                retry_approval_data['selected_uid'] = selected_uid
                retry_approval_data['selected_permission'] = permission.value
                if duration_seconds and duration_value not in (None, 'permanent'):
                    retry_approval_data['selected_duration'] = duration_value
                retry_approval_data['rotate_initial_checked'] = False
                retry_search_type = approval_data.get('search_type', 'record')
                rotation_subject = (
                    "PAM User record"
                    if retry_search_type == 'record'
                    else "PAM User folder"
                )
                retry_modal = build_search_modal(
                    query=approval_data.get('query', ''),
                    search_type=retry_search_type,
                    results=cached_results,
                    approval_data=retry_approval_data,
                    loading=False,
                    error_banner=(
                        f"Rotation is not configured on this {rotation_subject}. "
                        "Configure rotation in the Keeper Vault, or keep "
                        "*Rotate credentials when access expires* unchecked and approve again."
                    ),
                )
                try:
                    if defer_ack:
                        # Replace the still-open processing modal in place.
                        # view_id stays valid long after trigger_id expires.
                        client.views_update(
                            view_id=submitted_view_id,
                            view=retry_modal,
                        )
                        logger.info(
                            f"Pending [approval_id={approval_id}]: Rotation not configured for "
                            f"{request_type} (UID: {selected_uid}), requested by {user_email}, "
                            f"approver {approver_email}, requested permission {permission.value}, "
                            f"requested duration {duration_text}; modal updated with banner via views_update"
                        )
                    else:
                        client.views_open(
                            trigger_id=body.get("trigger_id"),
                            view=retry_modal,
                        )
                        logger.info(
                            f"Pending [approval_id={approval_id}]: Rotation not configured for "
                            f"{request_type} (UID: {selected_uid}), requested by {user_email}, "
                            f"approver {approver_email}, requested permission {permission.value}, "
                            f"requested duration {duration_text}; modal reopened with banner"
                        )
                except Exception as modal_error:
                    logger.warning(
                        f"Could not present search modal for rotation error: {modal_error}"
                    )
                    from ..utils import send_error_dm
                    send_error_dm(
                        client, approver_id, "Rotation Not Configured", error_msg
                    )
                return
            
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
                # Update the approval card to show it's invalid
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
            # Check if this is a permission conflict error
            elif is_permission_conflict_error(error_msg):
                # Permission conflict - don't update card, send DM to approver
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
                # Other error - update the approval card with error status
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
                
                # Show error to approver via modal or DM
                try:
                    from ..views import build_grant_error_modal
                    error_view = build_grant_error_modal(
                        title_text="Failed to Grant Access",
                        message=error_msg,
                    )
                    if defer_ack:
                        # Processing modal is still open - swap it in place.
                        client.views_update(
                            view_id=submitted_view_id,
                            view=error_view,
                        )
                    else:
                        client.views_open(
                            trigger_id=body.get("trigger_id"),
                            view=error_view,
                        )
                except Exception as modal_error:
                    # If we can't open/update a modal (trigger_id expired or
                    # view_id invalid), send DM to approver
                    logger.warning(f"Could not show error modal: {modal_error}")
                    from ..utils import send_error_dm
                    send_error_dm(client, approver_id, "Failed to Grant Access", error_msg)
            
    except Exception as e:
        logger.error(f"Error granting access from search modal: {e}")
        import traceback
        traceback.print_exc()

        # If we deferred the ack, the modal is still showing "Processing..."
        # Replace it with an error view so the admin isn't stuck.
        if defer_ack:
            try:
                from ..views import build_grant_error_modal
                client.views_update(
                    view_id=submitted_view_id,
                    view=build_grant_error_modal(
                        title_text="System Error",
                        message=f"An error occurred while processing your approval: {str(e)}",
                    ),
                )
            except Exception as inner_modal_error:
                logger.warning(
                    f"Could not update modal after unexpected error: {inner_modal_error}"
                )

        # Always also send a DM as a durable record/fallback.
        from ..utils import send_error_dm
        send_error_dm(
            client, body["user"]["id"],
            "System Error",
            f"An error occurred while processing your approval: {str(e)}"
        )


def handle_resync_vault_action(body: Dict[str, Any], client, config, keeper_client):
    """
    Handle the 'Re-sync Vault' button in the search modal.

    Runs Commander ``sync-down`` so records / folders created directly in the
    Keeper Vault (web UI, mobile, etc.) become visible to this Slack app
    without waiting for Commander Service Mode's background sync interval.
    Once the sync finishes we re-run the current search and refresh the modal
    in place. Errors are surfaced via the same DM + banner path used by
    regular Commander 401 / 403 failures.
    """
    view = body["view"]
    view_id = view["id"]
    values = view["state"]["values"]
    approval_data = json.loads(view["private_metadata"])

    new_query = (
        values.get("search_query", {})
        .get("update_search_query", {})
        .get("value", "")
        or ""
    ).strip()
    search_type = approval_data.get("search_type", "record")
    request_type = approval_data.get("type", "record")
    # OTS-only filter: drops PAM + NSF records that one-time-share can't operate on.
    for_one_time_share = request_type == "one_time_share"
    user_id = body["user"]["id"]

    from ..views import build_search_modal

    # Immediately swap the modal to a loading state so the user sees feedback
    # while sync-down runs (can take tens of seconds on large vaults).
    try:
        client.views_update(
            view_id=view_id,
            view=build_search_modal(
                query=new_query,
                search_type=search_type,
                results=[],
                approval_data=approval_data,
                loading=True,
            ),
        )
    except Exception as e:
        logger.debug(f"Could not show 'Syncing vault' state: {e}")

    # Pull latest vault state into Commander's local cache.
    logger.debug(f"Re-sync Vault triggered (search_type={search_type}, query='{new_query}')")
    ok, sync_error = keeper_client.sync_down()

    # Commander rejected sync-down (401 / 403) -> DM the admin + show banner.
    sync_banner = _maybe_commander_search_error_banner(
        client=client,
        user_id=user_id,
        search_error=sync_error,
        query=new_query,
        search_type=search_type,
    )
    if sync_banner:
        try:
            client.views_update(
                view_id=view_id,
                view=build_search_modal(
                    query=new_query,
                    search_type=search_type,
                    results=[],
                    approval_data=approval_data,
                    error_banner=sync_banner,
                ),
            )
        except Exception as e:
            logger.error(f"Failed to surface sync-down Commander error: {e}")
        return

    # Sync failed for other reasons (timeout / non-401-403 / exception).
    if not ok:
        try:
            client.views_update(
                view_id=view_id,
                view=build_search_modal(
                    query=new_query,
                    search_type=search_type,
                    results=[],
                    approval_data=approval_data,
                    error_banner=(
                        "Vault sync took longer than expected. "
                        "Showing cached results - try Re-sync Vault again in a moment."
                    ),
                ),
            )
        except Exception as e:
            logger.error(f"Failed to surface sync-down timeout: {e}")
        return

    # Sync succeeded -> drop any stale selection and re-run the current search
    # against the freshly synced cache.
    approval_data.pop("selected_uid", None)
    approval_data.pop("selected_folder_is_pam_user", None)

    if not new_query:
        # No query yet - just refresh the modal so the user can type one.
        try:
            client.views_update(
                view_id=view_id,
                view=build_search_modal(
                    query=new_query,
                    search_type=search_type,
                    results=[],
                    approval_data=approval_data,
                ),
            )
        except Exception as e:
            logger.error(f"Failed to refresh search modal after sync: {e}")
        return

    if search_type == "record":
        results, search_error = keeper_client.search_records(
            new_query, limit=20, for_one_time_share=for_one_time_share
        )
    else:
        results, search_error = keeper_client.search_folders(new_query, limit=20)

    sync_banner = _maybe_commander_search_error_banner(
        client=client,
        user_id=body.get("user", {}).get("id", ""),
        search_error=search_error,
        query=new_query,
        search_type=search_type,
    )

    try:
        client.views_update(
            view_id=view_id,
            view=build_search_modal(
                query=new_query,
                search_type=search_type,
                results=results,
                approval_data=approval_data,
                error_banner=sync_banner or None,
            ),
        )
        logger.debug(
            f"Re-sync Vault complete: {len(results)} result(s) for '{new_query}'"
        )
    except Exception as e:
        logger.error(f"Failed to update search modal after sync: {e}")


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

    # Drop any prior selection (and PAM-folder cache derived from it) when
    # running a new search.
    approval_data.pop("selected_uid", None)
    approval_data.pop("selected_folder_is_pam_user", None)
    
    # Re-run search. ``for_one_time_share`` filters PAM + NSF rows out for
    # OTS requests (Commander's ``one-time-share`` supports neither).
    request_type = approval_data.get("type", "record")
    for_one_time_share = request_type == "one_time_share"
    if search_type == "record":
        results, search_error = keeper_client.search_records(
            new_query, limit=20, for_one_time_share=for_one_time_share
        )
    else:
        results, search_error = keeper_client.search_folders(new_query, limit=20)

    refine_banner = _maybe_commander_search_error_banner(
        client=client,
        user_id=body.get("user", {}).get("id", ""),
        search_error=search_error,
        query=new_query,
        search_type=search_type,
    )
    
    # Build updated modal
    from ..views import build_search_modal
    updated_modal = build_search_modal(
        query=new_query,
        search_type=search_type,
        results=results,
        approval_data=approval_data,
        error_banner=refine_banner or None,
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
    
    auto_gen_selected = values.get("auto_gen_password", {}).get("auto_gen_checkbox", {}).get("selected_options", [])
    auto_gen_checked = any(opt.get("value") == "auto_gen" for opt in auto_gen_selected)

    # Vault-type toggle. ``use_classic=False`` -> create as a Nested Share Folder
    # record via ``nsf-record-add``; the self-destruct controls are not
    # rendered in that mode so we skip the related extraction entirely.
    use_classic = _is_classic_vault_checked(values)
    
    # Extract self-destruct checkbox and expiration (Classic only).
    self_destruct_enabled = False
    self_destruct_duration = None
    if use_classic:
        checkbox_options = values.get("self_destructive_actions", {}).get("self_destructive_checkbox", {}).get("selected_options", [])
        if checkbox_options and len(checkbox_options) > 0:
            self_destruct_enabled = True
            expiration_value = values.get("link_expiration", {}).get("expiration_select", {}).get("selected_option", {}).get("value")
            if expiration_value:
                self_destruct_duration = expiration_value  # e.g., "1h", "24h", "7d", etc.
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
    
    try:
        vault_label = "Classic" if use_classic else "Nested Share Folder"
        logger.info(
            f"Creating {vault_label} record '{title}' for requester {requester_id}"
            + (f" with self-destruct" if self_destruct_enabled else "")
        )
        generate_password = auto_gen_checked or (password.upper() == '$GEN' if password else False)

        if use_classic:
            create_result = keeper_client.create_record(
                title=title,
                login=login or None,
                password=None if generate_password else (password or None),
                url=url or None,
                notes=notes or None,
                generate_password=generate_password,
                self_destruct_duration=self_destruct_duration if self_destruct_enabled else None,
            )
        else:
            create_result = keeper_client.create_nsf_record(
                title=title,
                login=login or None,
                password=None if generate_password else (password or None),
                url=url or None,
                notes=notes or None,
                generate_password=generate_password,
            )
        
        if not create_result.get('success'):
            error_msg = create_result.get('error', 'Unknown error')
            # Re-render the create-record modal with the Commander error.
            if view_id:
                from ..views import build_create_record_modal
                error_modal = build_create_record_modal(
                    approval_data=metadata,
                    original_query=title,
                    use_classic=use_classic,
                    error=error_msg,
                )
                try:
                    client.views_update(view_id=view_id, view=error_modal)
                except Exception as e:
                    logger.error(f"Failed to render create-record error in modal: {e}")
                    from ..utils import send_error_dm
                    send_error_dm(client, body["user"]["id"], "Failed to create record", error_msg)
            else:
                from ..utils import send_error_dm
                send_error_dm(client, body["user"]["id"], "Failed to create record", error_msg)
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
            is_nsf=not use_classic,
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
            duration="5m",
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
    is_pam_user_folder = False
    if is_uid:
        folder_details = keeper_client.get_folder_by_uid(identifier)
        if not folder_details:
            return {"response_action": "errors", "errors": {"folder_identifier": f"No folder found with UID: {identifier}"}}
        
        # Validate it's actually a folder, not a record
        if folder_details.folder_type == 'record':
            return {"response_action": "errors", "errors": {"folder_identifier": "This is a record. Please use /keeper-request-record instead."}}

        # Detect PAM-user folder for the rotate-on-expire feature

        try:
            is_pam_user_folder, pam_folder_error = (
                keeper_client.is_pam_user_folder(identifier)
            )
        except Exception as e:
            logger.warning(
                f"is_pam_user_folder detection failed for {identifier}: {e}"
            )
            is_pam_user_folder = False
            pam_folder_error = None

        # Commander rejected list-sf (allowlist / auth). DM the requester
        if pam_folder_error:
            from ..utils import notify_commander_unauthorized_or_forbidden
            error_msg = notify_commander_unauthorized_or_forbidden(
                client=client,
                user_id=user_id,
                error=pam_folder_error,
                context_lines=[f"*Folder UID:* `{identifier}`"],
            )
            return {
                "response_action": "errors",
                "errors": {"folder_identifier": error_msg},
            }
    
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
            duration="5m",
            folder_details=folder_details,
            is_pam_user_folder=is_pam_user_folder,
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
            duration="5m",
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
