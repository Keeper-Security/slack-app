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

"""Background polling for Cloud SSO Device Approval requests."""

import threading
import time
from typing import Set

from ..logger import logger


class DeviceApprovalPoller:
    """
    Background poller for device approval requests.
    
    Polls Keeper Commander for pending device approvals and posts
    them to the configured Slack channel.
    """
    
    def __init__(self, slack_client, keeper_client, config, interval=120):
        self.slack_client = slack_client
        self.keeper_client = keeper_client
        self.config = config
        self.interval = interval
        self.seen_device_ids: Set[str] = set()
        self.running = False
        self.thread = None
        self._lock = threading.Lock()
    
    def start(self):
        """Start the background polling thread."""
        if self.running:
            logger.warning("Device approval poller already running")
            return
        
        logger.info("Starting Cloud SSO Device Approval poller (background)...")
        
        self.running = True
        self.thread = threading.Thread(target=self._poll_loop, daemon=True)
        self.thread.start()
        logger.ok(f"Cloud SSO Device Approval poller started (interval: {self.interval}s)")
    
    def stop(self):
        """Stop the background polling thread."""
        if not self.running:
            return
        
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        logger.info("Cloud SSO Device Approval poller stopped")
    
    def _poll_loop(self):
        """Main polling loop."""
        consecutive_errors = 0
        max_errors = 3
        
        while self.running:
            try:
                self._check_and_post_new_requests()
                consecutive_errors = 0
                
            except Exception as e:
                consecutive_errors += 1
                logger.error(f"Device approval polling error ({consecutive_errors}/{max_errors}): {e}")
                import traceback
                traceback.print_exc()
                
                # Stop polling after too many consecutive errors
                if consecutive_errors >= max_errors:
                    logger.warning("Device approval polling stopped (feature may not be available)")
                    self.running = False
                    break
            
            time.sleep(self.interval)
    
    def _check_and_post_new_requests(self):
        """Check for new pending device approvals and post them to Slack."""
        pending = self.keeper_client.get_pending_device_approvals()
        
        if not pending:
            with self._lock:
                if self.seen_device_ids:
                    logger.debug("No pending device approvals, clearing seen list")
                    self.seen_device_ids.clear()
            return
        
        current_ids = set()
        new_requests = []
        
        # Identify new requests (thread-safe)
        with self._lock:
            for device_data in pending:
                device_id = device_data.get('device_id')
                if not device_id:
                    continue
                
                current_ids.add(device_id)
                
                # Check if this is a NEW request
                if device_id not in self.seen_device_ids:
                    new_requests.append(device_data)
                    self.seen_device_ids.add(device_id)
                    logger.info(f"New device approval request: {device_id} ({device_data.get('device_name', 'Unknown')})")
        
        # Post only NEW requests to Slack
        if new_requests:
            logger.info(f"Posting {len(new_requests)} new device approval(s) to Slack")
            for device_data in new_requests:
                try:
                    from ..views import post_device_approval_request
                    post_device_approval_request(
                        client=self.slack_client,
                        approvals_channel=self.config.slack.approvals_channel_id,
                        device_data=device_data
                    )
                except Exception as e:
                    logger.error(f"Failed to post device approval {device_data.get('device_id')}: {e}")
        
        # Cleanup: remove device IDs that are no longer pending
        with self._lock:
            removed_ids = self.seen_device_ids - current_ids
            if removed_ids:
                logger.debug(f"Cleaning up {len(removed_ids)} resolved device approval(s)")
                self.seen_device_ids = self.seen_device_ids.intersection(current_ids)

