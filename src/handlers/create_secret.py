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

"""Handlers for /keeper-create-secret modal interactions."""

import json
from typing import Dict, Any
from ..logger import logger


def handle_create_secret_folder_select(ack, body: Dict[str, Any], client, config, keeper_client):
    """
    Shows loading state, fetches subfolders, then updates modal with record form.
    """
    values = body["view"]["state"]["values"]
    metadata = json.loads(body["view"]["private_metadata"])
    user_id = metadata["user_id"]
    
    selected = values.get("shared_folder_select", {}).get("shared_folder_choice", {}).get("selected_option")
    if not selected:
        ack()
        return
    
    folder_uid = selected["value"]
    folder_name = selected["text"]["text"]
    
    logger.info(f"User {user_id} selected shared folder: {folder_name} ({folder_uid})")
    
    # Keep the modal open with a loading state (ack must happen within 3s)
    ack(response_action="update", view={
        "type": "modal",
        "title": {"type": "plain_text", "text": "Create Secret"},
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f":hourglass_flowing_sand: Loading *{folder_name}*..."
                }
            }
        ]
    })
    
    try:
        subfolders = keeper_client.list_subfolders(folder_uid)
        
        from ..views import build_create_secret_record_form_modal
        form_modal = build_create_secret_record_form_modal(
            folder_name=folder_name,
            folder_uid=folder_uid,
            user_id=user_id,
            subfolders=subfolders if subfolders else None
        )
        
        client.views_update(
            view_id=body["view"]["id"],
            view=form_modal
        )
        
    except Exception as e:
        logger.error(f"Failed to load record form: {e}", exc_info=True)


def handle_create_secret_submit(ack, body: Dict[str, Any], client, config, keeper_client):
    """
    Creates the record, notifies admin, and shows confirmation to user.
    """
    values = body["view"]["state"]["values"]
    metadata = json.loads(body["view"]["private_metadata"])
    
    user_id = metadata["user_id"]
    folder_uid = metadata["folder_uid"]
    folder_name = metadata["folder_name"]
    
    title = (values.get("secret_title", {}).get("title_input", {}).get("value") or "").strip()
    login = (values.get("secret_login", {}).get("login_input", {}).get("value") or "").strip()
    password = (values.get("secret_password", {}).get("password_input", {}).get("value") or "").strip()
    url = (values.get("secret_url", {}).get("url_input", {}).get("value") or "").strip()
    notes = (values.get("secret_notes", {}).get("notes_input", {}).get("value") or "").strip()
    
    auto_gen_selected = values.get("auto_gen_password", {}).get("auto_gen_checkbox", {}).get("selected_options", [])
    auto_gen_checked = any(opt.get("value") == "auto_gen" for opt in auto_gen_selected)
    
    # Check for subfolder selection (text contains full path from tree command)
    subfolder_selected = values.get("subfolder_select", {}).get("subfolder_choice", {}).get("selected_option")
    target_folder_uid = folder_uid
    subfolder_path = None
    if subfolder_selected and subfolder_selected["value"] != folder_uid:
        target_folder_uid = subfolder_selected["value"]
        subfolder_path = subfolder_selected["text"]["text"]
    
    if not title:
        ack(response_action="errors", errors={"secret_title": "Title is required"})
        return
    
    if auto_gen_checked and password and password.upper() != '$GEN':
        ack(response_action="errors", errors={
            "secret_password": "Please either enter a password or check auto-generate, not both."
        })
        return
    
    folder_path = f"{folder_name} / {subfolder_path}" if subfolder_path else folder_name
    
    ack(response_action="update", view={
        "type": "modal",
        "title": {"type": "plain_text", "text": "Create Secret"},
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        ":hourglass_flowing_sand: *Creating your secret...*\n\n"
                        f"*Title:* {title}\n"
                        f"*Folder:* {folder_path}\n\n"
                        "Please wait, this may take a few seconds."
                    )
                }
            }
        ]
    })
    
    view_id = body["view"]["id"]
    
    logger.info(f"User {user_id} creating record '{title}' in folder {target_folder_uid}")
    
    try:
        generate_password = auto_gen_checked or (password.upper() == '$GEN' if password else False)
        
        result = keeper_client.create_record(
            title=title,
            login=login or None,
            password=None if generate_password else (password or None),
            url=url or None,
            notes=notes or None,
            generate_password=generate_password,
            folder_uid=target_folder_uid
        )
        
        if result.get('success'):
            record_uid = result.get('record_uid', 'Unknown')
            
            client.views_update(
                view_id=view_id,
                view={
                    "type": "modal",
                    "title": {"type": "plain_text", "text": "Create Secret"},
                    "close": {"type": "plain_text", "text": "Done"},
                    "blocks": [
                        {
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": (
                                    "*Record Created Successfully!*\n\n"
                                    f"*Title:* {title}\n"
                                    f"*Record UID:* `{record_uid}`\n"
                                    f"*Folder:* {folder_path}\n\n"
                                    "The record has been created in the Keeper vault."
                                )
                            }
                        }
                    ]
                }
            )
            
            from ..views import post_create_secret_notification
            post_create_secret_notification(
                client=client,
                approvals_channel=config.slack.approvals_channel_id,
                user_id=user_id,
                record_uid=record_uid,
                record_title=title,
                folder_name=folder_name,
                subfolder_name=subfolder_path
            )
            
            logger.ok(f"Record '{title}' ({record_uid}) created by {user_id} in {folder_path}")
        else:
            error_msg = result.get('error', 'Unknown error')
            logger.error(f"Failed to create record: {error_msg}")
            
            client.views_update(
                view_id=view_id,
                view={
                    "type": "modal",
                    "title": {"type": "plain_text", "text": "Create Secret"},
                    "close": {"type": "plain_text", "text": "Close"},
                    "blocks": [
                        {
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": (
                                    ":x: *Failed to Create Record*\n\n"
                                    f"Could not create record *{title}*:\n"
                                    f"_{error_msg}_\n\n"
                                    "Please try again or contact your administrator."
                                )
                            }
                        }
                    ]
                }
            )
            
    except Exception as e:
        logger.error(f"Exception in create secret submit: {e}", exc_info=True)
        try:
            client.views_update(
                view_id=view_id,
                view={
                    "type": "modal",
                    "title": {"type": "plain_text", "text": "Create Secret"},
                    "close": {"type": "plain_text", "text": "Close"},
                    "blocks": [
                        {
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": (
                                    ":x: *Error Creating Record*\n\n"
                                    f"An unexpected error occurred: _{str(e)}_\n\n"
                                    "Please try again or contact your administrator."
                                )
                            }
                        }
                    ]
                }
            )
        except Exception:
            logger.error("Failed to update modal with error state", exc_info=True)
