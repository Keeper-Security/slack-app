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

"""Handler for /keeper-create-secret slash command."""

from typing import Dict, Any
from ..logger import logger
from ..utils import get_user_email_from_slack


def handle_create_secret(body: Dict[str, Any], client, respond, config, keeper_client):
    """
    Handle /keeper-create-secret command.
    """
    user_id = body["user_id"]
    
    try:
        loading_response = client.views_open(
            trigger_id=body["trigger_id"],
            view={
                "type": "modal",
                "title": {"type": "plain_text", "text": "Create Secret"},
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": ":hourglass_flowing_sand: Loading shared folders..."
                        }
                    }
                ]
            }
        )
        view_id = loading_response["view"]["id"]
        
        user_email = get_user_email_from_slack(client, user_id)
        logger.info(f"User {user_id} ({user_email}) requesting create-secret")
        
        shared_folders = keeper_client.get_user_shared_folders(user_email)
        
        if not shared_folders:
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
                                "text": "No shared folders found for your account.\n\n"
                                        "Please ensure you have been granted access to "
                                        "at least one shared folder by your administrator."
                            }
                        }
                    ]
                }
            )
            return
        
        from ..views import build_create_secret_folder_select_modal
        modal = build_create_secret_folder_select_modal(
            shared_folders=shared_folders,
            user_id=user_id
        )
        
        client.views_update(
            view_id=view_id,
            view=modal
        )
        
    except Exception as e:
        logger.error(f"Failed to open create secret modal: {e}", exc_info=True)
        respond(
            text="Failed to open the create secret form. Please try again.",
            response_type="ephemeral"
        )
