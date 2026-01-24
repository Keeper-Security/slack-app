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

"""Background polling for PEDM approval requests."""

import threading
import time
from typing import Set

from ..logger import logger


class PEDMPoller:
    def __init__(self, slack_client, keeper_client, config, interval=120):
        self.slack_client = slack_client
        self.keeper_client = keeper_client
        self.config = config
        self.interval = interval
        self.seen_approval_uids: Set[str] = set()
        self.running = False
        self.thread = None
        self._lock = threading.Lock()  # Thread safety for seen_approval_uids
    
    def start(self):
        """Start the background polling thread."""
        if self.running:
            logger.warning("PEDM poller already running")
            return
        
        # Start poller optimistically - will fail gracefully if PEDM not available
        logger.info("Starting PEDM poller (background)...")
        
        self.running = True
        self.thread = threading.Thread(target=self._poll_loop, daemon=True)
        self.thread.start()
        logger.ok(f"PEDM poller started (interval: {self.interval}s)")
    
    def stop(self):
        """Stop the background polling thread."""
        if not self.running:
            return
        
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        logger.info("PEDM poller stopped")
    
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
                logger.error(f"PEDM polling error ({consecutive_errors}/{max_errors}): {e}", exc_info=True)
                
                # Stop polling after too many consecutive errors
                if consecutive_errors >= max_errors:
                    logger.warning("PEDM polling stopped (feature may not be available or configured)")
                    self.running = False
                    break
            
            time.sleep(self.interval)
    
    def _check_and_post_new_requests(self):
        """Check for new pending requests and post them to Slack."""
        pending = self.keeper_client.get_pending_pedm_requests()
        
        # None means API failure/timeout - don't clear seen list
        if pending is None:
            logger.debug("PEDM API failed/timed out, keeping seen list intact")
            return

        if len(pending) == 0:
            with self._lock:
                if self.seen_approval_uids:
                    logger.debug("No pending PEDM requests, clearing seen list")
                    self.seen_approval_uids.clear()
            return
        
        current_uids = set()
        new_requests = []
        
        # Identify new requests (thread-safe access to seen_approval_uids)
        with self._lock:
            for request_data in pending:
                approval_uid = request_data.get('approval_uid')
                if not approval_uid:
                    continue
                
                current_uids.add(approval_uid)
                
                # Check if this is a NEW request
                if approval_uid not in self.seen_approval_uids:
                    new_requests.append(request_data)
                    self.seen_approval_uids.add(approval_uid)
                    logger.info(f"New PEDM request detected: {approval_uid}")
        
        # Post only NEW requests to Slack (outside lock - no blocking during API calls)
        if new_requests:
            logger.info(f"Posting {len(new_requests)} new PEDM request(s) to Slack")
            for request_data in new_requests:
                try:
                    from ..views import post_pedm_approval_request
                    post_pedm_approval_request(
                        client=self.slack_client,
                        approvals_channel=self.config.slack.approvals_channel_id,
                        request_data=request_data
                    )
                except Exception as e:
                    logger.error(f"Failed to post PEDM request {request_data.get('approval_uid')}: {e}")
        
        # Cleanup: remove UIDs that are no longer pending (thread-safe)
        with self._lock:
            removed_uids = self.seen_approval_uids - current_uids
            if removed_uids:
                logger.debug(f"Cleaning up {len(removed_uids)} resolved PEDM request(s)")
                self.seen_approval_uids = self.seen_approval_uids.intersection(current_uids)
