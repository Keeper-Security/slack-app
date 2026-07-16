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

"""
Slack UI builders using Block Kit.
"""

import json
from typing import List, Dict, Any, Optional, Tuple
from .models import (
    RequestType,
    PermissionLevel,
    NSFPermissionRole,
    KeeperRecord,
    KeeperFolder,
)
from .utils import (
    format_timestamp,
    format_permission_name,
    format_duration,
    get_duration_options,
    sanitize_hyperlinks,
    is_pam_record_type,
    is_pam_user_record_type,
    results_contain_pam_record,
)
from .logger import logger

# Default Keeper server domain
DEFAULT_KEEPER_DOMAIN = "keepersecurity.com"


# ----------------------------------------------------------------------
# Nested Share Folder (NSF) helpers
# ----------------------------------------------------------------------

# Slack option values are a single string, so we pack the NSF flag onto the
# UID as a suffix instead of a separate field.
_NSF_VALUE_SUFFIX = "|nsf"


def encode_search_item_value(uid: str, is_nsf: bool) -> str:
    """
    Encode a search result's UID + NSF flag into a single Slack option
    value string. Nested Share Folder results get a ``|nsf`` suffix; classic
    results keep the raw UID.
    """
    if is_nsf:
        return f"{uid}{_NSF_VALUE_SUFFIX}"
    return uid


def decode_search_item_value(value: str) -> Tuple[str, bool]:
    """
    Reverse :func:`encode_search_item_value`. Returns ``(uid, is_nsf)``.
    Any value without the suffix is treated as classic.
    """
    if not value:
        return "", False
    if value.endswith(_NSF_VALUE_SUFFIX):
        return value[: -len(_NSF_VALUE_SUFFIX)], True
    return value, False


def _item_is_nsf(item: Any) -> bool:
    """
    Return the ``is_nsf`` flag from a search result, regardless
    of whether it's a fresh :class:`KeeperRecord` / :class:`KeeperFolder`
    instance or a cached-results dict surviving across modal updates.
    """
    if isinstance(item, dict):
        return bool(item.get('is_nsf', False))
    return bool(getattr(item, 'is_nsf', False))


def _item_uid(item: Any) -> str:
    """Pull the UID out of either a model instance or a cached dict."""
    if isinstance(item, dict):
        return item.get('uid', '') or ''
    return getattr(item, 'uid', '') or ''


def _item_title(item: Any) -> str:
    """
    Pull a human-friendly title out of a record or folder. Records use
    ``title``; folders use ``name``; cached dicts may use either.
    """
    if isinstance(item, dict):
        return item.get('title') or item.get('name') or 'Untitled'
    return getattr(item, 'title', None) or getattr(item, 'name', '') or 'Untitled'


def _results_nsf_flags(results: List[Any]) -> List[bool]:
    """
    Convenience for capturing the NSF flag for an entire result page in
    one pass (used when building Slack option lists).
    """
    return [_item_is_nsf(r) for r in results]


def post_approval_request(
    client,
    approvals_channel: str,
    approval_id: str,
    requester_id: str,
    requester_name: str,
    identifier: str,
    is_uid: bool,
    request_type: RequestType,
    justification: str,
    duration: str = "5m",
    record_details = None,
    folder_details = None,
    is_pam_user_folder: bool = False,
):
    """
    Post approval request message to approvals channel.
    """
    if request_type == RequestType.RECORD:
        title = "Record Access Request"
        item_type = "Record"
    elif request_type == RequestType.FOLDER:
        title = "Folder Access Request"
        item_type = "Folder"
    elif request_type == RequestType.ONE_TIME_SHARE:
        title = "One-Time Share Request"
        item_type = "Record"
    
    # Build action data
    action_data = {
        "approval_id": approval_id,
        "requester_id": requester_id,
        "identifier": identifier,
        "is_uid": is_uid,
        "type": request_type.value,
        "justification": justification,
        "duration": duration
    }
    
    # Sanitize justification to prevent malicious hyperlinks
    safe_justification = sanitize_hyperlinks(justification)
    
    # Sanitize identifier/UID to prevent URL injection
    safe_identifier = sanitize_hyperlinks(identifier)
    
    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": title}
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Requester:*\n<@{requester_id}>"},
                {"type": "mrkdwn", "text": f"*Request ID:*\n`{approval_id}`"},
                {"type": "mrkdwn", "text": f"*{item_type}:*\n`{safe_identifier}`"},
                {"type": "mrkdwn", "text": f"*Justification:*\n{safe_justification}"},
                {"type": "mrkdwn", "text": f"*Requested:*\n{format_timestamp()}"}
            ]
        },
        {"type": "divider"}
    ]
    
    # Add fetched details section for UID requests
    if is_uid and (record_details or folder_details):
        if record_details:
            details_text = f"*Title:* {record_details.title}\n"
            details_text += f"*Type:* {record_details.record_type.replace('_', ' ').title()}\n"
            if record_details.notes:
                # Truncate notes to 200 chars
                notes_preview = record_details.notes[:200] + "..." if len(record_details.notes) > 200 else record_details.notes
                details_text += f"*Description:* {notes_preview}"
            else:
                details_text += f"*Description:* _No description_"
        elif folder_details:
            folder_type_display = folder_details.folder_type.replace('_', ' ').title()
            details_text = f"*Title:* {folder_details.name}\n"
            details_text += f"*Type:* {folder_type_display}"
        
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*{item_type} Details*\n\n{details_text}"
            }
        })
        blocks.append({"type": "divider"})
    
    # If description (not UID), add search button
    if not is_uid:
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Action Required:* Approver must search for the correct {item_type.lower()}"
            },
            "accessory": {
                "type": "button",
                "text": {"type": "plain_text", "text": f"🔍 Search {item_type}s"},
                "action_id": f"search_{request_type.value}s",
                "value": json.dumps(action_data)
            }
        })
    else:
        # UID provided - add permission selector
        blocks.append(build_permission_selector_block(request_type))

        # Detect PAM-user targets once - drives both the duration filter
        # ("No Expiration" is incompatible with rotate-on-expire) and the
        # rotate-on-expire checkbox below.
        is_pam_user_record = (
            request_type == RequestType.RECORD
            and record_details
            and is_pam_user_record_type(record_details.record_type)
        )
        is_pam_folder = (
            request_type == RequestType.FOLDER
            and bool(is_pam_user_folder)
        )
        is_pam_target = bool(is_pam_user_record or is_pam_folder)

        # Add duration selector for approver
        blocks.append({
            "type": "section",
            "block_id": "duration_selector",
            "text": {
                "type": "mrkdwn",
                "text": "*Grant Access For:*"
            },
            "accessory": {
                "type": "static_select",
                "action_id": "select_duration",
                "placeholder": {
                    "type": "plain_text",
                    "text": "Select duration"
                },
                "options": get_duration_options(exclude_permanent=is_pam_target),
                "initial_option": {
                    "text": {"type": "plain_text", "text": "5 minutes"},
                    "value": "5m"
                }
            }
        })

        if is_pam_target:
            blocks.append(build_pam_rotate_on_expire_block())
            hint_text = (
                "_PAM User record: credentials will rotate when time-limited access expires (rotation must be configured on the record)._"
                if is_pam_user_record
                else "_PAM User folder: credentials in this folder will rotate when time-limited access expires (rotation must be configured on the underlying records)._"
            )
            blocks.append({
                "type": "context",
                "elements": [{
                    "type": "mrkdwn",
                    "text": hint_text,
                }],
            })
            action_data["is_pam"] = True
    
    # Add approve/deny buttons based on request type
    if is_uid:
        # UID provided - show both Approve and Deny
        blocks.append({
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Approve"},
                    "style": "primary",
                    "action_id": "approve_request",
                    "value": json.dumps(action_data)
                },
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Deny"},
                    "style": "danger",
                    "action_id": "deny_request",
                    "value": json.dumps(action_data)
                }
            ]
        })
    else:
        # Description provided - only show Deny (must search to approve)
        blocks.append({
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Deny Request"},
                    "style": "danger",
                    "action_id": "deny_request",
                    "value": json.dumps(action_data)
                }
            ]
        })

    
    client.chat_postMessage(
        channel=approvals_channel,
        blocks=blocks,
        text=f"{title} from @{requester_name}",
        unfurl_links=False,
        unfurl_media=False
    )

def build_pam_rotate_on_expire_block(
    for_modal: bool = False,
    initial_checked: bool = True,
) -> Dict[str, Any]:
    """
    Checkbox to rotate PAM credentials when time-limited share access expires.
    """
    option = {
        "text": {"type": "plain_text", "text": "Rotate credentials when access expires"},
        "value": "rotate_on_expire",
    }
    checkbox_element = {
        "type": "checkboxes",
        "action_id": "pam_rotate_checkbox",
        "options": [option],
    }
    if initial_checked:
        checkbox_element["initial_options"] = [option]
    if for_modal:
        return {
            "type": "input",
            "block_id": "pam_rotate_block",
            "optional": True,
            "label": {"type": "plain_text", "text": "PAM credential rotation"},
            "element": checkbox_element,
        }
    return {
        "type": "actions",
        "block_id": "pam_rotate_actions",
        "elements": [checkbox_element],
    }


def _build_nsf_permission_options(
    request_type: RequestType,
) -> List[Dict[str, Any]]:
    """
    Build the option list for Nested Share Folder role-based permissions.
    """
    options = [
        {
            "text": {"type": "plain_text", "text": "Viewer (read-only)"},
            "value": NSFPermissionRole.VIEWER.value,
        },
        {
            "text": {"type": "plain_text", "text": "Share Manager"},
            "value": NSFPermissionRole.SHARE_MANAGER.value,
        },
        {
            "text": {"type": "plain_text", "text": "Content Manager"},
            "value": NSFPermissionRole.CONTENT_MANAGER.value,
        },
        {
            "text": {"type": "plain_text", "text": "Content & Share Manager"},
            "value": NSFPermissionRole.CONTENT_SHARE_MANAGER.value,
        },
        {
            "text": {"type": "plain_text", "text": "Full Manager"},
            "value": NSFPermissionRole.FULL_MANAGER.value,
        },
    ]
    if request_type != RequestType.FOLDER:
        options.append({
            "text": {"type": "plain_text", "text": "Transfer Ownership"},
            "value": NSFPermissionRole.TRANSFER_OWNER.value,
        })
    return options


def build_permission_selector_block(
    request_type: RequestType,
    for_modal: bool = False,
    initial_value: Optional[str] = None,
    is_nsf: bool = False,
) -> Dict[str, Any]:
    """
    Build permission level selector block.
    """
    if is_nsf and request_type != RequestType.ONE_TIME_SHARE:
        options = _build_nsf_permission_options(request_type)
        initial_option = options[0]
        if initial_value:
            for opt in options:
                if opt.get("value") == initial_value:
                    initial_option = opt
                    break

        if for_modal:
            return {
                "type": "input",
                "block_id": "permission_selector",
                "dispatch_action": True,
                "label": {
                    "type": "plain_text",
                    "text": "Select Permission Level (Nested Share Folder)",
                },
                "element": {
                    "type": "static_select",
                    "action_id": "select_permission",
                    "placeholder": {"type": "plain_text", "text": "Choose role"},
                    "initial_option": initial_option,
                    "options": options,
                },
            }
        return {
            "type": "section",
            "text": {"type": "mrkdwn", "text": "*Select Permission Level (Nested Share Folder):*"},
            "accessory": {
                "type": "static_select",
                "action_id": "select_permission",
                "placeholder": {"type": "plain_text", "text": "Choose role"},
                "initial_option": initial_option,
                "options": options,
            },
        }

    if request_type == RequestType.ONE_TIME_SHARE:
        # One-time shares only support View Only and Can Edit
        options = [
            {
                "text": {"type": "plain_text", "text": "View Only"},
                "value": PermissionLevel.VIEW_ONLY.value
            },
            {
                "text": {"type": "plain_text", "text": "Can Edit"},
                "value": PermissionLevel.CAN_EDIT.value
            }
        ]
        default_index = 0  # "View Only" by default for one-time shares
        initial_option = options[default_index]
    elif request_type == RequestType.RECORD:
        options = [
            {
                "text": {"type": "plain_text", "text": "View Only"},
                "value": PermissionLevel.VIEW_ONLY.value
            },
            {
                "text": {"type": "plain_text", "text": "Can Edit"},
                "value": PermissionLevel.CAN_EDIT.value
            },
            {
                "text": {"type": "plain_text", "text": "Can Share"},
                "value": PermissionLevel.CAN_SHARE.value
            },
            {
                "text": {"type": "plain_text", "text": "Edit and Share"},
                "value": PermissionLevel.EDIT_AND_SHARE.value
            },
            {
                "text": {"type": "plain_text", "text": "Change Owner"},
                "value": PermissionLevel.CHANGE_OWNER.value
            }
        ]
        default_index = 0  # "View Only" by default (minimum access)
        initial_option = options[default_index]
    else:  # FOLDER
        options = [
            {
                "text": {"type": "plain_text", "text": "No User Permissions"},
                "value": PermissionLevel.NO_PERMISSIONS.value
            },
            {
                "text": {"type": "plain_text", "text": "Can Manage Users"},
                "value": PermissionLevel.MANAGE_USERS.value
            },
            {
                "text": {"type": "plain_text", "text": "Can Manage Records"},
                "value": PermissionLevel.MANAGE_RECORDS.value
            },
            {
                "text": {"type": "plain_text", "text": "Can Manage Records and Users"},
                "value": PermissionLevel.MANAGE_ALL.value
            }
        ]
        default_index = 0  # "No User Permissions" by default
        initial_option = options[default_index]

    if initial_value:
        for opt in options:
            if opt.get("value") == initial_value:
                initial_option = opt
                break
    
    if for_modal:
        # Use input block for full-width dropdown (better display for long text in modals)
        return {
            "type": "input",
            "block_id": "permission_selector",
            "dispatch_action": True,  # Dispatch action immediately when selection changes
            "label": {
                "type": "plain_text",
                "text": "Select Permission Level"
            },
            "element": {
                "type": "static_select",
                "action_id": "select_permission",
                "placeholder": {"type": "plain_text", "text": "Choose permission level"},
                "initial_option": initial_option,
                "options": options
            }
        }
    else:
        # Use section block with accessory for messages (inline display)
        return {
            "type": "section",
            "text": {"type": "mrkdwn", "text": "*Select Permission Level:*"},
            "accessory": {
                "type": "static_select",
                "action_id": "select_permission",
                "placeholder": {"type": "plain_text", "text": "Choose permission level"},
                "initial_option": initial_option,
                "options": options
            }
        }

def build_grant_processing_modal(
    message: str = "Granting access. This may take a few seconds...",
) -> Dict[str, Any]:
    return {
        "type": "modal",
        "callback_id": "grant_processing_modal",
        "title": {"type": "plain_text", "text": "Granting Access..."},
        "close": {"type": "plain_text", "text": "Cancel"},
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f":hourglass_flowing_sand: *{message}*",
                },
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": "_This usually takes a few seconds. Please don't close this window._",
                    }
                ],
            },
        ],
    }


def build_grant_success_modal(
    title_text: str,
    detail_lines: List[str],
) -> Dict[str, Any]:
    """
    Build a success confirmation modal shown after a deferred-ack grant flow
    completes. Lets the admin dismiss the modal with a Close button.
    """
    text_lines = [f"*{title_text}*", ""] + detail_lines
    return {
        "type": "modal",
        "callback_id": "grant_success_modal",
        "title": {"type": "plain_text", "text": "Access Granted"},
        "close": {"type": "plain_text", "text": "Close"},
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "\n".join(text_lines),
                },
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": "_The approval card and the requester have been notified._",
                    }
                ],
            },
        ],
    }


def build_grant_error_modal(
    title_text: str,
    message: str,
    footer: str = "Please try again with different settings if needed, or contact the requester directly.",
) -> Dict[str, Any]:
    """
    Build a generic error modal shown after a deferred-ack grant flow fails
    with an error that does not have a tailored recovery flow.
    """
    return {
        "type": "modal",
        "callback_id": "grant_error_modal",
        "title": {"type": "plain_text", "text": "Error"},
        "close": {"type": "plain_text", "text": "Close"},
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": title_text},
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": message},
            },
            {"type": "divider"},
            {
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": footer}
                ],
            },
        ],
    }


def build_search_modal(
    query: str,
    search_type: str,
    results: List[Any],
    approval_data: Dict[str, Any],
    loading: bool = False,
    show_duration: bool = True,
    error_banner: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Build search results modal with interactive search.
    """
    # Determine request type from approval_data, fallback to search_type
    if 'type' in approval_data:
        try:
            request_type = RequestType(approval_data['type'])
        except (ValueError, KeyError):
            # Fallback if invalid type
            request_type = RequestType.RECORD if search_type == "record" else RequestType.FOLDER
    else:
        request_type = RequestType.RECORD if search_type == "record" else RequestType.FOLDER
    
    # Store search type and results in metadata for handler (needed early for action buttons and dynamic updates)
    metadata = approval_data.copy()
    metadata['search_type'] = search_type
    metadata['query'] = query

    # Catalog mode (approver boundary scoping active): the results list is the
    # admin-curated set of allowed items for this approver's team, not a
    # Commander search. All UI tweaks below are purely additive so single-
    # channel / boundary-off flows render byte-for-byte the same as before.
    _catalog_mode = bool(approval_data.get('catalog_mode'))
    _catalog_scope_size = approval_data.get('scope_size') if _catalog_mode else None
    
    # Cache results as serializable dicts (KeeperRecord/KeeperFolder objects can't be JSON serialized)
    if results:
        if isinstance(results[0], dict):
            metadata['cached_results'] = [
                {
                    'uid': r.get('uid', ''),
                    'title': r.get('title', 'Untitled'),
                    'record_type': r.get('record_type', ''),
                    'is_nsf': bool(r.get('is_nsf', False)),
                }
                for r in results[:10]
            ]
        else:
            metadata['cached_results'] = [
                {
                    'uid': r.uid,
                    'title': r.title if hasattr(r, 'title') else r.name,
                    'record_type': getattr(r, 'record_type', ''),
                    'is_nsf': bool(getattr(r, 'is_nsf', False)),
                }
                for r in results[:10]
            ]
    else:
        metadata['cached_results'] = []
    
    blocks = []
    if error_banner:
        blocks.append({
            "type": "section",
            "block_id": "error_banner",
            "text": {"type": "mrkdwn", "text": f":warning: {error_banner}"},
        })
        blocks.append({"type": "divider"})

    # Catalog-mode disclosure banner. Rendered at the top of the modal so
    # approvers see the restriction rule before scanning results. Wording is
    # kind-aware (records vs folders) so it matches whichever modal is open.
    # Purely additive: only appears when maybe_catalog_fetch set catalog_mode
    # in approval_data (i.e. boundary scoping is active for this kind).
    if _catalog_mode:
        _kind_word = "records" if search_type == "record" else "folders"
        blocks.append({
            "type": "section",
            "block_id": "catalog_scope_banner",
            "text": {
                "type": "mrkdwn",
                "text": (
                    ":lock: *Approver scope active.* You can only view and "
                    f"approve {_kind_word} configured for your team. To see "
                    f"or approve other {_kind_word}, ask your Keeper admin "
                    "to add them to your team's scope."
                ),
            },
        })
        blocks.append({"type": "divider"})

    if _catalog_mode:
        _search_label = "Filter Your Allowed Items"
        _search_placeholder = "Type to filter within your team's allowed items..."
        _search_hint = (
            "Filters the list of items your team is allowed to approve. "
            "Click Refine to apply."
        )
    else:
        _search_label = "Search Term"
        _search_placeholder = "Type your search query..."
        _search_hint = "Modify the search term and click the Refine button below"
    blocks.append({
        "type": "input",
        "block_id": "search_query",
        "label": {"type": "plain_text", "text": _search_label},
        "element": {
            "type": "plain_text_input",
            "action_id": "update_search_query",
            "initial_value": query,
            "placeholder": {"type": "plain_text", "text": _search_placeholder}
        },
        "hint": {
            "type": "plain_text",
            "text": _search_hint,
        }
    })

    if _catalog_mode and not loading:
        _scope_note = (
            f"Showing {len(results)} of {_catalog_scope_size} item(s) "
            f"allowed for your team."
            if isinstance(_catalog_scope_size, int)
            else f"Showing {len(results)} item(s) allowed for your team."
        )
        blocks.append({
            "type": "context",
            "elements": [{
                "type": "mrkdwn",
                "text": f":lock: *Approver scope active.* {_scope_note}",
            }],
        })
    
    # Build action buttons (Refine Search + optionally Create New Record)
    # Use slim metadata for button values
    button_metadata = {k: v for k, v in metadata.items() if k != 'cached_results'}
    
    action_buttons = [
        {
            "type": "button",
            "text": {"type": "plain_text", "text": "Refine Search"},
            "action_id": "refine_search_action",
            "value": json.dumps(button_metadata)
        }
    ]
    
    # Add "Create New Record" button beside Refine (only for description-based
    # RECORD requests). Gate on the resolved request_type enum: the type lives
    # under the 'type' key in approval_data, so the old 'request_type' key check
    # never matched and the button wrongly showed for one-time-share requests.
    # OTS shares an existing record's link, so creating a new record is N/A.
    if (search_type == "record" and
        request_type != RequestType.ONE_TIME_SHARE and
        not approval_data.get('is_uid', False)):
        action_buttons.append({
            "type": "button",
            "text": {"type": "plain_text", "text": "Create New Record"},
            "style": "primary",
            "action_id": "create_new_record_action",
            "value": json.dumps(button_metadata)
        })
    
    # Add the combined action block
    blocks.append({
        "type": "actions",
        "elements": action_buttons
    })
    
    # Add helpful context if Create button is shown
    if len(action_buttons) > 1:
        blocks.append({
            "type": "context",
            "elements": [{
                "type": "mrkdwn",
                "text": "_Or create a new record and share it_"
            }]
        })
    
    # Results-count line doubles as the anchor for the "Re-sync Vault" button:
    # rendering it as a section + accessory keeps the button visually attached
    # to the line it controls (refresh the current search/list) without taking
    # up its own row, and lets us hide the accessory during the loading state
    # so a slow sync can't be double-triggered. Also hidden in catalog mode
    # (approver scope active): the list is a fixed admin-curated UID set, so
    # sync-down cannot surface new items and is misleading there.
    if loading:
        results_text = "_Searching..._"
    elif _catalog_mode:
        _q_suffix = f" matching `{query}`" if query else ""
        results_text = f"_Showing {len(results)} allowed item(s){_q_suffix}_"
    else:
        results_text = f"_Showing {len(results)} result(s) for: `{query}`_"
    results_block: Dict[str, Any] = {
        "type": "section",
        "text": {"type": "mrkdwn", "text": results_text},
    }
    if not loading and not _catalog_mode:
        results_block["accessory"] = {
            "type": "button",
            "text": {
                "type": "plain_text",
                "text": ":arrows_counterclockwise: Re-sync Vault",
                "emoji": True,
            },
            "action_id": "resync_vault_action",
            "value": json.dumps(button_metadata),
            "accessibility_label": "Re-sync vault to fetch records created in the Keeper Vault",
        }
    blocks.extend([
        results_block,
        {"type": "divider"},
    ])
    
    if results:
        # Add radio button selector for results
        options = []
        initial_option = None  # Will be set if newly_created_uid or selected_uid matches
        newly_created_uid = approval_data.get('newly_created_uid')
        selected_uid = approval_data.get('selected_uid')
        selected_record_is_pam_user = False

        selected_folder_is_pam_user = bool(
            search_type == "folder"
            and approval_data.get('selected_folder_is_pam_user', False)
        )


        selected_uid_norm, _ = decode_search_item_value(selected_uid) if selected_uid else ('', False)


        nsf_flags = _results_nsf_flags(results[:10])
        is_mixed_results = len(set(nsf_flags)) > 1
        is_one_time_share = request_type == RequestType.ONE_TIME_SHARE

        selected_item_is_nsf = nsf_flags[0] if (nsf_flags and not is_mixed_results) else False

        selection_resolved = False

        for item in results[:10]:  # Limit to 10 for UX
            uid = _item_uid(item)
            title = _item_title(item)
            item_is_nsf = _item_is_nsf(item)
            if isinstance(item, dict):
                item_record_type = item.get('record_type', '')
            elif isinstance(item, KeeperRecord):
                item_record_type = getattr(item, 'record_type', '')
            else:  # KeeperFolder
                item_record_type = ''

            # OTS searches already exclude NSF records, so the Classic/NSF
            # badge adds noise there. Keep it for normal share flows where
            # mixed Classic + NSF results are possible.
            if is_one_time_share:
                text = f"{title} ({uid})"
            else:
                badge = "[NSF]" if item_is_nsf else "[Classic]"
                text = f"{badge} {title} ({uid})"
            value = encode_search_item_value(uid, item_is_nsf)

            option = {
                "text": {"type": "plain_text", "text": text},
                "value": value
            }
            options.append(option)

            # Pre-select if this is the newly created record or the user just clicked it.
            if selected_uid_norm and uid == selected_uid_norm:
                initial_option = option
                selected_item_is_nsf = item_is_nsf
                selection_resolved = True
                if is_pam_user_record_type(item_record_type):
                    selected_record_is_pam_user = True
            elif not selected_uid_norm and newly_created_uid and uid == newly_created_uid:
                initial_option = option
                selected_item_is_nsf = item_is_nsf
                selection_resolved = True

        # Single combined flag drives duration filtering + rotate checkbox.
        selected_target_is_pam = bool(
            selected_record_is_pam_user or selected_folder_is_pam_user
        )
        
        # If we have a newly created record, add context message
        if initial_option and not selected_uid:
            blocks.insert(-1, {  # Insert before the last divider
                "type": "context",
                "elements": [{
                    "type": "mrkdwn",
                    "text": f"New record '{approval_data.get('newly_created_title', '')}' created"
                }]
            })
        
        radio_block = {
            "type": "input",
            "block_id": "selected_item",
            "label": {"type": "plain_text", "text": f"Select {search_type}:"},
            "dispatch_action": True,  # Refresh modal on selection (for PAM rotate checkbox)
            "element": {
                "type": "radio_buttons",
                "action_id": "item_selection",
                "options": options
            },
            "optional": False  # Make selection required
        }
        
        # Add initial_option if we have a newly created record or current selection
        if initial_option:
            radio_block["element"]["initial_option"] = initial_option
            logger.info(
                f"Pre-selecting record uid={initial_option['value']} "
                f"(selected_uid={selected_uid}, newly_created_uid={newly_created_uid})"
            )
        else:
            logger.info(f"No pre-selection - newly_created_uid: {newly_created_uid}")
        
        blocks.append(radio_block)


        if is_mixed_results and not selection_resolved:
            blocks.append({
                "type": "context",
                "elements": [{
                    "type": "mrkdwn",
                    "text": (
                        "_Results include both *Classic* and *Nested Share "
                        "Folder* items. Pick one above to load the matching "
                        "permission options._"
                    ),
                }],
            })


        show_permission_controls = (not is_mixed_results) or selection_resolved
        if approval_data.get('create_self_destruct', False):
            # Self-destruct mode - show info message instead of selectors
            duration_text = approval_data.get('self_destruct_duration', 'N/A')
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Self-Destruct Record Settings*\n\nRecord will be shared directly to requester's vault\nAuto-deletes after: *{duration_text}*\nAccess: View-Only"
                }
            })
        elif show_permission_controls:
            selected_permission = approval_data.get('selected_permission')
            selected_duration = approval_data.get('selected_duration')
            rotate_initial_checked = approval_data.get('rotate_initial_checked', True)


            # OTS has its own View Only / Can Edit model and NSF records are
            # filtered out before rendering, so don't show Classic/NSF mode
            # context there.
            if not is_one_time_share:
                if selected_item_is_nsf:
                    blocks.append({
                        "type": "context",
                        "elements": [{
                            "type": "mrkdwn",
                            "text": ":file_folder: *Nested Share Folder* — role-based permissions",
                        }],
                    })
                else:
                    blocks.append({
                        "type": "context",
                        "elements": [{
                            "type": "mrkdwn",
                            "text": ":key: *Classic Share Folder* — standard share permissions",
                        }],
                    })


            blocks.append(
                build_permission_selector_block(
                    request_type,
                    for_modal=True,
                    initial_value=selected_permission,
                    is_nsf=selected_item_is_nsf,
                )
            )
            
            # Add duration selector (conditionally based on permission)
            if show_duration:
                # For PAM user targets (records or folders), "No Expiration"
                # is incompatible with rotate-on-expire and is hidden.
                duration_options = get_duration_options(
                    exclude_permanent=selected_target_is_pam
                )
                # If the previously selected duration was "permanent" but we
                # just switched to a PAM user target, fall back to 5 minutes
                # so the initial_option always resolves to something in the list.
                effective_duration = selected_duration
                if selected_target_is_pam and effective_duration == "permanent":
                    effective_duration = "5m"
                duration_initial = {
                    "text": {"type": "plain_text", "text": "5 minutes"},
                    "value": "5m",
                }
                if effective_duration:
                    for opt in duration_options:
                        if opt.get("value") == effective_duration:
                            duration_initial = opt
                            break
                blocks.append({
                    "type": "input",
                    "block_id": "grant_duration",
                    "label": {"type": "plain_text", "text": "Grant Access For"},
                    "optional": True,
                    "element": {
                        "type": "static_select",
                        "action_id": "grant_duration_select",
                        "options": duration_options,
                        "initial_option": duration_initial,
                    },
                    "hint": {
                        "type": "plain_text",
                        "text": "Select how long the access should remain active"
                    }
                })
                if (
                    request_type != RequestType.ONE_TIME_SHARE
                    and selected_target_is_pam
                ):
                    blocks.append(
                        build_pam_rotate_on_expire_block(
                            for_modal=True,
                            initial_checked=rotate_initial_checked,
                        )
                    )
                    hint_text = (
                        "_Selected PAM User record: credentials rotate when time-limited access expires (rotation must be configured on the record)._"
                        if selected_record_is_pam_user
                        else "_Selected PAM User folder: credentials in this folder will rotate when time-limited access expires (rotation must be configured on the underlying records)._"
                    )
                    blocks.append({
                        "type": "context",
                        "elements": [{
                            "type": "mrkdwn",
                            "text": hint_text,
                        }],
                    })
            else:
                # Show permanent access notice
                blocks.append({
                    "type": "context",
                    "elements": [{
                        "type": "mrkdwn",
                        "text": "ℹ️ *Permanent Access:* The selected permission does not support time limits."
                    }]
                })
        # else: mixed-flavour results with no selection yet -- the radio
        # button's ``dispatch_action`` will re-render this modal and the
        # permission controls will appear at that point.

        if len(results) > 10:
            blocks.append({
                "type": "context",
                "elements": [{
                    "type": "mrkdwn",
                    "text": f"_Showing 10 of {len(results)} results_"
                }]
            })
    else:
        # Show loading or no results message
        if loading:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f":hourglass_flowing_sand: *Searching...*\n\nFetching {search_type}s matching `{query}` from Keeper vault..."
                }
            })
            blocks.append({
                "type": "context",
                "elements": [{
                    "type": "mrkdwn",
                    "text": "_This may take a few seconds. The modal will update automatically when results are ready._"
                }]
            })
        else:
            if _catalog_mode:
                if isinstance(_catalog_scope_size, int) and _catalog_scope_size == 0:
                    message_text = (
                        f"No {search_type}s are currently allowed for your team.\n\n"
                        "_Contact your Keeper admin to add "
                        f"{search_type} UIDs to your team's approval scope._"
                    )
                elif query:
                    message_text = (
                        f"No allowed {search_type}s match `{query}`.\n\n"
                        "_Clear the filter and click 'Refine Search' to see "
                        "your team's full allowed list._"
                    )
                else:
                    message_text = (
                        f"None of your team's allowed {search_type} UIDs are "
                        "currently readable (they may have been deleted or "
                        "you may not have access).\n\n"
                        "_Contact your Keeper admin to review the team's "
                        "approval scope._"
                    )
            else:
                message_text = (
                    f"No {search_type}s found matching `{query}`\n\n"
                    "_Try modifying your search above and click "
                    "'Refine Search' to see updated results_"
                )

            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": message_text
                }
            })
    
    # Modal configuration
    modal_config = {
        "type": "modal",
        "callback_id": "search_modal_submit",
        "private_metadata": json.dumps(metadata),
        "title": {"type": "plain_text", "text": f"Search {search_type.capitalize()}s"},
        # No close button - users can press ESC to dismiss
        "blocks": blocks
    }

    # Submit button is required by Slack when modal has input blocks
    if results:
        # Change button text based on mode
        if approval_data.get('create_self_destruct', False):
            modal_config["submit"] = {"type": "plain_text", "text": "Share Record"}
        else:
            modal_config["submit"] = {"type": "plain_text", "text": "Approve Access"}
    else:
        # When no results, submit performs search
        modal_config["submit"] = {"type": "plain_text", "text": "Done"}
    
    return modal_config

def build_create_record_modal(
    approval_data: Dict[str, Any],
    original_query: str = "",
    show_expiration: bool = False,
    use_classic: bool = False,
    error: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Build modal for creating a new record.
    After creation, will return to search modal with new record pre-selected.

    ``error`` renders a banner at the top (e.g. a Commander password-policy
    rejection) so the user can correct the input and resubmit in place.
    """
    is_nsf = not use_classic

    blocks: List[Dict[str, Any]] = []

    if error:
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f":x: *Could not create record*\n```{error}```",
            },
        })
        blocks.append({"type": "divider"})

    blocks.extend([
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Creating record for:* <@{approval_data.get('requester_id')}>\n_After creation, you'll be able to review and approve sharing_"
                }
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": ":warning: Auto-generate password to keep it fully private. Generated passwords stay in your Keeper Vault (zero-knowledge), while manually entered passwords pass through Slack."
                    }
                ]
            },
            {"type": "divider"},
    ])


    classic_option = {
        "text": {"type": "plain_text", "text": "Use Classic permission model"},
        "value": "classic",
    }
    vault_checkbox = {
        "type": "checkboxes",
        "action_id": "classic_vault_checkbox",
        "options": [classic_option],
    }
    if use_classic:
        vault_checkbox["initial_options"] = [classic_option]
    blocks.append({
        "type": "section",
        "block_id": "classic_vault",
        "text": {"type": "mrkdwn", "text": "*Vault Type* _(optional)_"},
        "accessory": vault_checkbox,
    })
    if is_nsf:
        blocks.append({
            "type": "context",
            "elements": [{
                "type": "mrkdwn",
                "text": "_Unchecked = Nested Share Folder record (role-based sharing). Self-destruct is Classic-only._",
            }],
        })
    blocks.append({"type": "divider"})

    blocks.extend([
            {
                "type": "input",
                "block_id": "record_type",
                "label": {"type": "plain_text", "text": "Record Type"},
                "element": {
                    "type": "static_select",
                    "action_id": "type_select",
                    "placeholder": {"type": "plain_text", "text": "Select record type"},
                    "initial_option": {
                        "text": {"type": "plain_text", "text": "Login"},
                        "value": "login"
                    },
                    "options": [
                        {
                            "text": {"type": "plain_text", "text": "Login"},
                            "value": "login"
                        }
                    ]
                }
            },
            {
                "type": "input",
                "block_id": "record_title",
                "label": {"type": "plain_text", "text": "Title (Required)"},
                "element": {
                    "type": "plain_text_input",
                    "action_id": "title_input",
                    "initial_value": original_query,
                    "placeholder": {"type": "plain_text", "text": "Title"}
                }
            },
            {
                "type": "input",
                "block_id": "record_login",
                "label": {"type": "plain_text", "text": "Login (Required)"},
                "element": {
                    "type": "plain_text_input",
                    "action_id": "login_input",
                    "placeholder": {"type": "plain_text", "text": "Email or Username"}
                }
            },
            {
                "type": "input",
                "block_id": "auto_gen_password",
                "label": {"type": "plain_text", "text": "Password Generation"},
                "element": {
                    "type": "checkboxes",
                    "action_id": "auto_gen_checkbox",
                    "options": [
                        {
                            "text": {"type": "plain_text", "text": "\ud83c\udfb2 Auto-generate password"},
                            "value": "auto_gen"
                        }
                    ]
                },
                "optional": True
            },
            {
                "type": "input",
                "block_id": "record_password",
                "label": {"type": "plain_text", "text": "Password"},
                "element": {
                    "type": "plain_text_input",
                    "action_id": "password_input",
                    "placeholder": {"type": "plain_text", "text": "Enter password (or check auto-generate above)"}
                },
                "optional": True
            },
            {
                "type": "input",
                "block_id": "record_url",
                "label": {"type": "plain_text", "text": "Website Address"},
                "element": {
                    "type": "plain_text_input",
                    "action_id": "url_input",
                    "placeholder": {"type": "plain_text", "text": "https://"}
                },
                "optional": True
            },
            {
                "type": "input",
                "block_id": "record_notes",
                "label": {"type": "plain_text", "text": "Notes"},
                "element": {
                    "type": "plain_text_input",
                    "action_id": "notes_input",
                    "multiline": True,
                    "placeholder": {"type": "plain_text", "text": "Notes"}
                },
                "optional": True
            },
            {"type": "divider"}
    ])

    if not is_nsf:
        checkbox_block = {
            "type": "actions",
            "block_id": "self_destructive_actions",
            "elements": [
                {
                    "type": "checkboxes",
                    "action_id": "self_destructive_checkbox",
                    "options": [
                        {
                            "text": {"type": "plain_text", "text": "Enable self-destruct (optional)"},
                            "value": "enabled"
                        }
                    ]
                }
            ]
        }

        # Pre-check the checkbox if expiration dropdown should be shown
        if show_expiration:
            checkbox_block["elements"][0]["initial_options"] = [
                {
                    "text": {"type": "plain_text", "text": "Enable self-destruct (optional)"},
                    "value": "enabled"
                }
            ]

        blocks.append(checkbox_block)
    
    # Conditionally add expiration dropdown only if checkbox is checked
    if (not is_nsf) and show_expiration:
        blocks.append({
            "type": "input",
            "block_id": "link_expiration",
            "label": {"type": "plain_text", "text": "Link Expires In"},
            "element": {
                "type": "static_select",
                "action_id": "expiration_select",
                "placeholder": {"type": "plain_text", "text": "Select expiration time"},
                "initial_option": {
                    "text": {"type": "plain_text", "text": "5 minutes"},
                    "value": "5m"
                },
                "options": [
                    {"text": {"type": "plain_text", "text": "5 minutes"},  "value": "5m"},
                    {"text": {"type": "plain_text", "text": "10 minutes"}, "value": "10m"},
                    {"text": {"type": "plain_text", "text": "30 minutes"}, "value": "30m"},
                    {"text": {"type": "plain_text", "text": "1 hour"},     "value": "1h"},
                    {"text": {"type": "plain_text", "text": "24 hours"},   "value": "24h"},
                    {"text": {"type": "plain_text", "text": "1 week"},     "value": "7d"},
                    {"text": {"type": "plain_text", "text": "30 days"},    "value": "30d"},
                    {"text": {"type": "plain_text", "text": "90 days"},    "value": "90d"},
                ]
            }
        })
    
    return {
        "type": "modal",
        "callback_id": "create_record_modal_submit",
        "private_metadata": json.dumps(approval_data),
        "title": {"type": "plain_text", "text": "Create New Record"},
        "submit": {"type": "plain_text", "text": "Create Record"},
        "close": {"type": "plain_text", "text": "Cancel"},
        "blocks": blocks
    }

def update_approval_message(
    client,
    channel_id: str,
    message_ts: str,
    status: str,
    original_blocks: List[Dict]
):
    """
    Update approval message with status.
    """
    # Remove action buttons
    updated_blocks = []
    for block in original_blocks:
        if block.get("type") == "actions":
            continue
        if block.get("type") == "section" and block.get("accessory"):
            continue
        if block.get("type") == "input":
            continue
        updated_blocks.append(block)
    
    # Add status section
    updated_blocks.append({
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": f"*Status:* {status}\n*Updated:* {format_timestamp()}"
        }
    })
    
    client.chat_update(
        channel=channel_id,
        ts=message_ts,
        text=status,  # Fallback text for notifications and accessibility
        blocks=updated_blocks
    )

def _get_vault_deep_link(item_type: str, uid: str, server_domain: str = DEFAULT_KEEPER_DOMAIN) -> str:
    """
    Generate Keeper vault deep link URL for records or folders.
    """
    if item_type == "record":
        return f"https://{server_domain}/vault/#detail/{uid}"
    else:  # folder
        return f"https://{server_domain}/vault/#shared_folder/{uid}"

def send_access_granted_dm(
    client,
    user_id: str,
    approval_id: str,
    item_type: str,
    item_title: str,
    share_url: str,
    expires_at: str,
    uid: str = None,
    permission: str = None,
    server_domain: str = DEFAULT_KEEPER_DOMAIN
):
    """Send DM to requester when access is granted."""
    try:
        dm_response = client.conversations_open(users=[user_id])
        dm_channel_id = dm_response["channel"]["id"]
        
        # Build the message with detailed information
        message = f"*Access Granted!*\n\n" \
                  f"*Request ID:* `{approval_id}`\n" \
                  f"*{item_type.capitalize()}:* {item_title}\n"
        
        # Add deep link instead of UID
        if uid:
            deep_link = _get_vault_deep_link(item_type, uid, server_domain)
            message += f"*{item_type.capitalize()} Link:* <{deep_link}|Open in Vault>\n"
        
        # Add share URL only if it's a one-time share link
        if share_url and share_url != 'N/A':
            message += f"*Share URL:* {share_url}\n"
        
        # Add permission if provided
        if permission:
            message += f"*Permission:* {permission}\n"
        
        message += f"*Expires:* {expires_at}\n\n"

        client.chat_postMessage(
            channel=dm_channel_id,
            text=message
        )
    except Exception as e:
        logger.error(f"Failed to send DM to {user_id}: {e}")

def send_access_denied_dm(
    client,
    user_id: str,
    approval_id: str,
    item_type: str,
    approver_name: str
):
    """Send DM to requester when access is denied."""
    client.chat_postMessage(
        channel=user_id,
        text=f"*Access Request Denied*\n\n"
             f"Request ID: `{approval_id}`\n"
             f"{item_type.capitalize()} access request was denied by {approver_name}.\n\n"
             f"If you believe this was in error, please contact your manager or the security team."
    )

def send_share_link_dm(
    client,
    user_id: str,
    record_uid: str,
    share_url: str,
    record_title: str = None,
    expires_at: str = None,
    approval_id: str = None
):
    """
    Send one-time share link via DM.
    """
    # Build message
    message = f"*One-Time Share Link Created*\n\n"
    
    if record_title:
        message += f"*Record:* {record_title}\n"
    message += f"*UID:* `{record_uid}`\n"
    
    if approval_id:
        message += f"*Request ID:* `{approval_id}`\n"
    
    message += f"\n*Share Link:*\n{share_url}\n\n"
    
    if expires_at:
        message += f"*Expires:* {expires_at}\n\n"
    message += "*Security Notice:*\n"
    message += "• This link can only be opened on ONE device\n"
    message += "• It expires after first access or time limit\n"
    message += "• Share only via secure channels (email, SMS, etc.)\n"
    message += "• Do NOT post in public Slack channels\n"
    message += "• Keep this link confidential"
    
    try:
        dm_response = client.conversations_open(users=[user_id])
        dm_channel = dm_response["channel"]["id"]
        
        client.chat_postMessage(
            channel=dm_channel,
            text=message
        )
    except Exception as e:
        logger.error(f"Failed to send share link DM: {e}")

def format_timestamp(timestamp_str: Optional[str] = None) -> str:
    """
    Format ISO timestamp for display.
    """
    from datetime import datetime
    
    if timestamp_str is None:
        # No timestamp provided, use current time
        return datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    try:
        dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return timestamp_str

def post_pedm_approval_request(
    client,
    approvals_channel: str,
    request_data: dict
):
    """
    Post PEDM approval request to Slack channel.
    """
    from .models import PEDMRequest
    from datetime import datetime, timedelta
    
    # Parse request data
    try:
        request = PEDMRequest.from_dict(request_data)
    except Exception as e:
        logger.error(f"Failed to parse PEDM request: {e}")
        return
    
    # Calculate expiration
    try:
        created_dt = datetime.fromisoformat(request.created.replace('Z', '+00:00'))
        expires_dt = created_dt + timedelta(minutes=request.expire_in)
        expires_str = expires_dt.strftime('%Y-%m-%d %H:%M:%S')
    except Exception as e:
        logger.warning(f"Could not parse expiration time: {e}")
        expires_str = f"{request.expire_in} minutes from creation"
    
    # function to truncate long text
    def truncate_text(text: str, max_length: int = 150) -> str:
        """Truncate text if too long, adding ellipsis."""
        if not text:
            return text
        if len(text) <= max_length:
            return text
        return text[:max_length - 3] + "..."
    
    # Build command details based on approval type
    if request.approval_type == "CommandLine":
        # For CommandLine
        command_details_text = f"*Executable:* `{request.file_name}`\n"
        command_details_text += f"*Path:* `{request.file_path}`\n"
        command_details_text += f"*Command:* `{request.command}`\n"
        command_details_text += f"*Description:* {request.description}"
        command_details_fields = None  # Use text block instead
    else:  # PrivilegeElevation
        if request.file_path and request.file_name:
            path_separator = '\\' if '\\' in request.file_path or ':' in request.file_path else '/'
            full_path = f"{request.file_path}{path_separator}{request.file_name}"
        else:
            full_path = request.command if request.command else "Unknown"
        command_details_fields = [
            {"type": "mrkdwn", "text": f"*Executable:*\n`{truncate_text(request.file_name)}`"},
            {"type": "mrkdwn", "text": f"*Path:*\n`{truncate_text(request.file_path)}`"},
            {"type": "mrkdwn", "text": f"*Full Path:*\n`{truncate_text(full_path)}`"},
            {"type": "mrkdwn", "text": f"*Description:*\n{truncate_text(request.description)}"}
        ]
    
    # Build approval card
    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": "Privilege Elevation Approval Request"}
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*User:*\n{request.username}"},
                {"type": "mrkdwn", "text": f"*Request ID:*\n`{request.approval_uid}`"},
                {"type": "mrkdwn", "text": f"*Type:*\n{request.approval_type}"},
                {"type": "mrkdwn", "text": f"*Expires:*\n{expires_str}"},
                {"type": "mrkdwn", "text": f"*Created:*\n{format_timestamp(request.created)}"},
                {"type": "mrkdwn", "text": f"*Agent UID:*\n`{request.agent_uid}`"}
            ]
        },
        {"type": "divider"},
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*Command Details*"
            }
        }
    ]

    if command_details_fields is None:
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": command_details_text
            }
        })
    else:
        # PrivilegeElevation type(grid layout)
        blocks.append({
            "type": "section",
            "fields": command_details_fields
        })
    
    # Add justification (sanitized to prevent URL injection)
    safe_justification = sanitize_hyperlinks(request.justification) if request.justification else '_No justification provided_'
    blocks.append({
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": f"*Justification:*\n{safe_justification}"
        }
    })
    
    # Continue building blocks
    blocks.extend([
        {"type": "divider"},
        {
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Approve"},
                    "style": "primary",
                    "action_id": "approve_pedm_request",
                    "value": request.approval_uid
                },
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Deny"},
                    "style": "danger",
                    "action_id": "deny_pedm_request",
                    "value": request.approval_uid
                }
            ]
        }
    ])
    
    try:
        client.chat_postMessage(
            channel=approvals_channel,
            blocks=blocks,
            text=f"PEDM Approval Request from {request.username}",
            unfurl_links=False,
            unfurl_media=False
        )
        logger.ok(f"Posted PEDM request {request.approval_uid} to Slack")
    except Exception as e:
        logger.error(f"Failed to post PEDM request to Slack: {e}")


def post_device_approval_request(
    client,
    approvals_channel: str,
    device_data: dict
):
    """
    Post Cloud SSO Device Approval request to Slack channel.
    """
    device_id = device_data.get('device_id', 'Unknown')
    device_name = device_data.get('device_name', 'Unknown Device')
    device_type = device_data.get('device_type', 'Unknown')
    client_version = device_data.get('client_version', 'Unknown')
    email = device_data.get('email', 'Unknown')
    ip_address = device_data.get('ip_address', 'Unknown')
    request_date = device_data.get('date', 'Unknown')
    
    # Build approval card
    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": "Cloud SSO Device Approval Request"}
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*User Email:*\n{email}"},
                {"type": "mrkdwn", "text": f"*Device ID:*\n`{device_id}`"},
                {"type": "mrkdwn", "text": f"*Device Name:*\n{device_name}"},
                {"type": "mrkdwn", "text": f"*Device Type:*\n{device_type}"},
                {"type": "mrkdwn", "text": f"*Client Version:*\n{client_version}"},
                {"type": "mrkdwn", "text": f"*IP Address:*\n`{ip_address}`"}
            ]
        },
        {
            "type": "context",
            "elements": [
                {"type": "mrkdwn", "text": f"*Requested:* {request_date}"}
            ]
        },
        {"type": "divider"},
        {
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Approve Device"},
                    "style": "primary",
                    "action_id": "approve_device",
                    "value": device_id
                },
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Deny Device"},
                    "style": "danger",
                    "action_id": "deny_device",
                    "value": device_id
                }
            ]
        }
    ]
    
    try:
        client.chat_postMessage(
            channel=approvals_channel,
            blocks=blocks,
            text=f"Cloud SSO Device Approval Request from {email} - {device_name}"
        )
        logger.ok(f"Posted device approval request {device_id} to Slack")
    except Exception as e:
        logger.error(f"Failed to post device approval to Slack: {e}")


def build_request_modal(
    user_id: str,
    user_name: str,
    channel_id: str,
    response_url: str = "",
    request_type: str = "record"
) -> Dict[str, Any]:
    """
    Build modal for access requests when user runs command without arguments.
    """
    config = {
        "record": {
            "callback_id": "request_record_modal_submit",
            "title": "Request Record Access",
            "header": "*Request access to a record*\n\nFill in the details below to submit your request for approval.",
            "block_id": "record_identifier",
            "label": "Record UID or Description",
            "placeholder": 'Record UID, Title or Description'
        },
        "folder": {
            "callback_id": "request_folder_modal_submit",
            "title": "Request Folder Access",
            "header": "*Request access to a folder*\n\nFill in the details below to submit your request for approval.",
            "block_id": "folder_identifier",
            "label": "Folder UID or Description",
            "placeholder": 'Folder UID, Folder Name or Description'
        },
        "one_time_share": {
            "callback_id": "one_time_share_modal_submit",
            "title": "One-Time Share",
            "header": "*Request a one-time share link*\n\nFill in the details below to submit your request for approval.",
            "block_id": "record_identifier",
            "label": "Record UID or Description",
            "placeholder": 'Record UID or Description'
        }
    }
    
    cfg = config[request_type]
    
    return {
        "type": "modal",
        "callback_id": cfg["callback_id"],
        "title": {"type": "plain_text", "text": cfg["title"]},
        "submit": {"type": "plain_text", "text": "Submit Request"},
        "close": {"type": "plain_text", "text": "Cancel"},
        "private_metadata": json.dumps({
            "user_id": user_id,
            "user_name": user_name,
            "channel_id": channel_id,
            "response_url": response_url
        }),
        "blocks": [
            {"type": "section", "text": {"type": "mrkdwn", "text": cfg["header"]}},
            {"type": "divider"},
            {
                "type": "input",
                "block_id": cfg["block_id"],
                "label": {"type": "plain_text", "text": cfg["label"]},
                "element": {
                    "type": "plain_text_input",
                    "action_id": "identifier_input",
                    "placeholder": {"type": "plain_text", "text": cfg["placeholder"]}
                }
            },
            {
                "type": "input",
                "block_id": "justification",
                "label": {"type": "plain_text", "text": "Justification"},
                "element": {
                    "type": "plain_text_input",
                    "action_id": "justification_input",
                    "multiline": True,
                    "placeholder": {"type": "plain_text", "text": "Justification or Ticket Number"}
                }
            }
        ]
    }


def build_create_secret_folder_select_modal(
    shared_folders: List[Dict[str, Any]],
    user_id: str
) -> Dict[str, Any]:
    """
    Build modal for selecting a shared folder (Step 1 of create secret flow).
    """
    folder_options = []
    for folder in shared_folders[:100]:
        name = folder.get('name', 'Untitled')
        uid = folder.get('uid', '')
        if uid:
            folder_options.append({
                "text": {"type": "plain_text", "text": name[:75]},
                # Encode the NSF flag onto the option value (same |nsf suffix
                # scheme as the search modal) so the downstream handler can
                # route to nsf-record-add vs record-add without re-querying.
                "value": encode_search_item_value(uid, folder.get('is_nsf', False))
            })
    
    metadata = json.dumps({"user_id": user_id})
    
    blocks = [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*Create a new secret record*\n\nSelect the shared folder where you want to create the record."
            }
        },
        {"type": "divider"},
        {
            "type": "input",
            "block_id": "shared_folder_select",
            "label": {"type": "plain_text", "text": "Shared Folder"},
            "element": {
                "type": "static_select",
                "action_id": "shared_folder_choice",
                "placeholder": {"type": "plain_text", "text": "Select a shared folder"},
                "options": folder_options
            }
        }
    ]
    
    return {
        "type": "modal",
        "callback_id": "create_secret_folder_select",
        "private_metadata": metadata,
        "title": {"type": "plain_text", "text": "Create Secret"},
        "submit": {"type": "plain_text", "text": "Next"},
        "close": {"type": "plain_text", "text": "Cancel"},
        "blocks": blocks
    }


def build_create_secret_record_form_modal(
    folder_name: str,
    folder_uid: str,
    user_id: str,
    subfolders: Optional[List[Dict[str, Any]]] = None,
    parent_is_nsf: bool = False,
) -> Dict[str, Any]:
    """
    Build modal for entering record details (Step 2 of create secret flow).
    Optionally includes a subfolder dropdown if subfolders exist.
    """
    metadata = json.dumps({
        "user_id": user_id,
        "folder_uid": folder_uid,
        "folder_name": folder_name,
        "parent_is_nsf": parent_is_nsf,
    })
    
    blocks = [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Creating record in:* `{folder_name}`"
            }
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": ":warning: Auto-generate password to keep it fully private. Generated passwords stay in your Keeper Vault (zero-knowledge), while manually entered passwords pass through Slack."
                }
            ]
        },
        {"type": "divider"}
    ]
    
    if subfolders:
        subfolder_options = [
            {
                "text": {"type": "plain_text", "text": "(Parent folder)"},
                "value": encode_search_item_value(folder_uid, parent_is_nsf)
            }
        ]
        for sf in subfolders[:99]:
            path = sf.get('path', sf.get('name', 'Untitled'))
            uid = sf.get('uid', '')
            if uid:
                subfolder_options.append({
                    "text": {"type": "plain_text", "text": path[:75]},
                    # Encode each subfolder's own NSF flag so the submit
                    # handler can route per-target (a Classic parent can hold
                    # NSF subfolders and vice versa).
                    "value": encode_search_item_value(uid, sf.get('is_nsf', False))
                })
        
        blocks.append({
            "type": "input",
            "block_id": "subfolder_select",
            "label": {"type": "plain_text", "text": "Subfolder"},
            "element": {
                "type": "static_select",
                "action_id": "subfolder_choice",
                "placeholder": {"type": "plain_text", "text": "Select a subfolder"},
                "options": subfolder_options,
                "initial_option": subfolder_options[0]
            },
            "optional": True
        })
    
    blocks.extend([
        {
            "type": "input",
            "block_id": "secret_title",
            "label": {"type": "plain_text", "text": "Title"},
            "element": {
                "type": "plain_text_input",
                "action_id": "title_input",
                "placeholder": {"type": "plain_text", "text": "Record title"}
            }
        },
        {
            "type": "input",
            "block_id": "secret_login",
            "label": {"type": "plain_text", "text": "Login"},
            "element": {
                "type": "plain_text_input",
                "action_id": "login_input",
                "placeholder": {"type": "plain_text", "text": "Email or username"}
            },
            "optional": True
        },
        {
            "type": "input",
            "block_id": "auto_gen_password",
            "label": {"type": "plain_text", "text": "Password Generation"},
            "element": {
                "type": "checkboxes",
                "action_id": "auto_gen_checkbox",
                "options": [
                    {
                        "text": {"type": "plain_text", "text": "\ud83c\udfb2 Auto-generate password"},
                        "value": "auto_gen"
                    }
                ]
            },
            "optional": True
        },
        {
            "type": "input",
            "block_id": "secret_password",
            "label": {"type": "plain_text", "text": "Password"},
            "element": {
                "type": "plain_text_input",
                "action_id": "password_input",
                "placeholder": {"type": "plain_text", "text": "Enter password (or check auto-generate above)"}
            },
            "optional": True
        },
        {
            "type": "input",
            "block_id": "secret_url",
            "label": {"type": "plain_text", "text": "Website Address"},
            "element": {
                "type": "plain_text_input",
                "action_id": "url_input",
                "placeholder": {"type": "plain_text", "text": "https://"}
            },
            "optional": True
        },
        {
            "type": "input",
            "block_id": "secret_notes",
            "label": {"type": "plain_text", "text": "Notes"},
            "element": {
                "type": "plain_text_input",
                "action_id": "notes_input",
                "multiline": True,
                "placeholder": {"type": "plain_text", "text": "Additional notes"}
            },
            "optional": True
        },
    ])
    
    return {
        "type": "modal",
        "callback_id": "create_secret_submit",
        "private_metadata": metadata,
        "title": {"type": "plain_text", "text": "Create Secret"},
        "submit": {"type": "plain_text", "text": "Create Record"},
        "close": {"type": "plain_text", "text": "Cancel"},
        "blocks": blocks
    }


def post_create_secret_notification(
    client,
    approvals_channel: str,
    user_id: str,
    record_uid: str,
    record_title: str,
    folder_name: str,
    subfolder_name: Optional[str] = None
):
    """
    Post notification to admin channel when a user creates a secret record.
    No sensitive data (password, login) is included.
    """
    folder_path = folder_name
    if subfolder_name and subfolder_name != folder_name:
        folder_path = f"{folder_name} / {subfolder_name}"
    
    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": "New Secret Record Created"}
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*User:*\n<@{user_id}>"},
                {"type": "mrkdwn", "text": f"*Record UID:*\n`{record_uid}`"},
                {"type": "mrkdwn", "text": f"*Title:*\n{record_title}"},
                {"type": "mrkdwn", "text": f"*Folder:*\n{folder_path}"}
            ]
        },
        {
            "type": "context",
            "elements": [{
                "type": "mrkdwn",
                "text": f"Created via `/keeper-create-secret` • {format_timestamp()}"
            }]
        }
    ]
    
    try:
        client.chat_postMessage(
            channel=approvals_channel,
            blocks=blocks,
            text=f"User <@{user_id}> added record {record_uid} to {folder_path}",
            unfurl_links=False,
            unfurl_media=False
        )
    except Exception as e:
        logger.error(f"Failed to post create secret notification: {e}")
