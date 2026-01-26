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
Keeper Service Mode API client.
All backend Logic is being written in this module.
"""

import requests
import shlex
import re
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta

from .models import (
    KeeperRecord,
    KeeperFolder,
    PermissionLevel
)
from .config import KeeperConfig
from .logger import logger


class KeeperClient:
    """
    Interacting with Keeper Commander Service Mode API.
    """
    
    def __init__(self, config: KeeperConfig):
        """
        Initialize Keeper client.
        """
        self.base_url = config.service_url
        self.api_key = config.api_key
        
        # Create session for connection pooling
        self.session = requests.Session()
        
        if self.api_key:
            self.session.headers.update({
                'api-key': self.api_key,
                'Content-Type': 'application/json'
            })
        
        # Fetch and cache server domain
        self.server_domain = self._fetch_server_domain()
    
    def health_check(self) -> bool:
        """
        It Checks if Keeper Service Mode is accessible or not.
        """
        try:
            response = self.session.get(f'{self.base_url}/queue/status', timeout=5)
            return response.status_code == 200
        except Exception:
            return False
    
    def _fetch_server_domain(self) -> str:
        """
        Fetch the Keeper server domain using the 'server' command.
        """
        default_domain = "keepersecurity.com"
        
        try:
            response = self.session.post(
                f'{self.base_url}/executecommand-async',
                json={"command": "server"},
                timeout=10
            )
            
            if response.status_code != 202:
                logger.warning(f"Failed to fetch server domain: {response.status_code}, using default")
                return default_domain
            
            result = response.json()
            request_id = result.get('request_id')
            
            if not request_id:
                logger.warning("No request_id for server command, using default domain")
                return default_domain
            
            # Poll for result
            result_data = self._poll_for_result(request_id, max_wait=10)
            
            if not result_data:
                logger.warning("Server command timed out, using default domain")
                return default_domain
            
            if result_data.get('status') == 'success':
                return result_data.get('message', default_domain)
            else:
                logger.warning("Server command failed, using default domain")
                return default_domain
                
        except Exception as e:
            logger.warning(f"Exception fetching server domain: {e}, using default")
            return default_domain
    
    def update_credentials(self, service_url: str, api_key: Optional[str] = None):
        """
        Update the client credentials dynamically without restart the slack app server.
        """
        # Update base URL
        self.base_url = service_url
        
        # Update API key and session headers
        if api_key:
            self.api_key = api_key
            self.session.headers.update({
                'api-key': api_key,
                'Content-Type': 'application/json'
            })
        
        logger.ok(f"Keeper client credentials updated: {self.base_url}")
    
    def _sanitize_search_query(self, query: str) -> str:
        """
        Sanitize search query to prevent command injection.
        Removes dangerous shell characters.
        """
        if not query:
            return query
        
        # Characters that could be used for command injection
        dangerous_chars = [';', '|', '&', '$', '`', '(', ')', '{', '}', '[', ']', 
                          '!', '\\', '\n', '\r', '\x00', '<', '>', '"', "'"]
        
        sanitized = query
        for char in dangerous_chars:
            sanitized = sanitized.replace(char, '')
        
        return sanitized.strip()
    
    def search_records(self, query: str, limit: int = 20) -> List[KeeperRecord]:
        """
        Search for records using Service Mode search command with category filter.
        """
        try:
            # Sanitize query to prevent command injection
            safe_query = self._sanitize_search_query(query)
            if not safe_query:
                logger.debug("Empty query after sanitization")
                return []
            
            response = self.session.post(
                f'{self.base_url}/executecommand-async',
                json={"command": f'search -c r "{safe_query}" --format=json'},
                timeout=10
            )
            
            if response.status_code != 202:
                logger.debug(f"Failed to submit search command: {response.status_code}")
                return []
            
            result = response.json()
            request_id = result.get('request_id')
            
            if not request_id:
                logger.debug("No request_id received")
                return []
            
            # Poll for result
            result_data = self._poll_for_result(request_id, max_wait=30)
            
            if result_data:
                return self._parse_search_records_results(result_data, limit)
            else:
                logger.debug("Search command timed out or failed")
                return []
                
        except Exception as e:
            logger.debug(f"Error searching records: {e}")
            import traceback
            traceback.print_exc()
        return []
    
    def search_folders(self, query: str, limit: int = 20) -> List[KeeperFolder]:
        """
        Search for shared folders using Service Mode search command with category filter.
        """
        try:
            # Sanitize query to prevent command injection
            safe_query = self._sanitize_search_query(query)
            if not safe_query:
                logger.debug("Empty query after sanitization")
                return []
            
            # Use search command with shared folder category filter (-c s)
            response = self.session.post(
                f'{self.base_url}/executecommand-async',
                json={"command": f'search -c s "{safe_query}" --format=json'},
                timeout=10
            )
            
            if response.status_code != 202:
                logger.debug(f"Failed to submit search command: {response.status_code}")
                return []
            
            result = response.json()
            request_id = result.get('request_id')
            
            if not request_id:
                logger.debug("No request_id received")
                return []
            
            # Poll for result with smart backoff
            result_data = self._poll_for_result(request_id, max_wait=10)
            
            if result_data:
                # Parse results (no client-side filtering needed - search does it)
                return self._parse_search_folders_results(result_data, limit)
            else:
                logger.debug("Search command timed out or failed")
                return []
                
        except Exception as e:
            logger.debug(f"Error searching folders: {e}")
            import traceback
            traceback.print_exc()
        return []
    
    def get_record_by_uid(self, record_uid: str) -> Optional[KeeperRecord]:
        """
        Get record details by UID using Service Mode.
        """

        try:
            # Submit search command with UID
            response = self.session.post(
                f'{self.base_url}/executecommand-async',
                json={"command": f"search {record_uid} --format=json"},
                timeout=10
            )
            
            if response.status_code != 202:
                logger.error(f"Failed to submit search command: {response.status_code}")
                return None
            
            result_data = response.json()
            result_id = result_data.get('request_id')
            
            if not result_id:
                logger.error("No result_id in response")
                return None
            
            # Poll for results
            final_result = self._poll_for_result(result_id)
            
            if not final_result:
                logger.warning(f"No record found for UID: {record_uid}")
                return None
            
            # Parse the search results - data is directly in the response
            data = final_result.get('data')
            
            if not data or not isinstance(data, list) or len(data) == 0:
                logger.warning(f"No records in search results for UID: {record_uid}")
                return None

            record_data = data[0]
            
            # Extract basic fields
            title = record_data.get('name', 'Untitled Record')
            uid = record_data.get('uid', record_uid)

            # Check the 'type' field FIRST - this tells us if it's a folder or record
            item_type = record_data.get('type', 'record')
            
            # Initialize notes
            notes = ''
            
            # If it's a folder type, preserve that type
            if item_type in ['shared_folder', 'user_folder', 'folder']:
                record_type = item_type
                logger.info(f"Found folder: {title} (type: {record_type})")
            else:
                # For records, parse details for more specific type (login, etc.)
                details_str = record_data.get('details', '')
                record_type = 'login'  # default for records
                
                if details_str:
                    parts = details_str.split(', ')
                    for part in parts:
                        if part.startswith('Type: '):
                            record_type = part.replace('Type: ', '').strip()
                        elif part.startswith('Description: '):
                            notes = part.replace('Description: ', '').strip()
                
                logger.info(f"Found record: {title} (type: {record_type})")
            
            return KeeperRecord(
                uid=uid,
                title=title,
                record_type=record_type,
                folder_uid=None,
                notes=notes
            )
            
        except Exception as e:
            logger.error(f"Failed to get record {record_uid}: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def get_record_owner(self, record_uid: str) -> Optional[str]:
        """
        Get the owner email of a record.
        """
        try:
            response = self.session.post(
                f'{self.base_url}/executecommand-async',
                json={"command": f"get --format=json {record_uid}"},
                timeout=10
            )
            
            if response.status_code != 202:
                logger.error(f"Failed to submit get command: {response.status_code}")
                return None
            
            result_data = response.json()
            request_id = result_data.get('request_id')
            
            if not request_id:
                logger.error("No request_id in response")
                return None
            
            # Poll for results
            final_result = self._poll_for_result(request_id)
            
            if not final_result:
                logger.warning(f"No result for record UID: {record_uid}")
                return None

            data = final_result.get('data')
            
            if not data:
                logger.warning(f"No data in get result for UID: {record_uid}")
                return None

            user_permissions = data.get('user_permissions', [])
            
            for user_perm in user_permissions:
                if user_perm.get('owner', False):
                    owner_email = user_perm.get('username')
                    logger.info(f"Found record owner: {owner_email}")
                    return owner_email
            
            logger.warning(f"No owner found in user_permissions for record: {record_uid}")
            return None
            
        except Exception as e:
            logger.error(f"Failed to get record owner for {record_uid}: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def get_folder_by_uid(self, folder_uid: str) -> Optional[KeeperFolder]:
        """
        Get folder details by UID using Service Mode.
        """

        try:
            # Submit search command with UID
            response = self.session.post(
                f'{self.base_url}/executecommand-async',
                json={"command": f"search {folder_uid} --format=json"},
                timeout=10
            )
            
            if response.status_code != 202:
                logger.error(f"Failed to submit search command: {response.status_code}")
                return None
            
            result_data = response.json()
            result_id = result_data.get('request_id')
            
            if not result_id:
                logger.error("No result_id in response")
                return None
            
            # Poll for results
            final_result = self._poll_for_result(result_id)
            
            if not final_result:
                logger.warning(f"No folder found for UID: {folder_uid}")
                return None

            data = final_result.get('data')

            if not data or not isinstance(data, list) or len(data) == 0:
                logger.warning(f"No folders in search results for UID: {folder_uid}")
                return None

            folder_data = data[0]
            
            # Extract basic fields
            name = folder_data.get('name', 'Untitled Folder')
            uid = folder_data.get('uid', folder_uid)
            folder_type = folder_data.get('type', 'folder')
            
            logger.info(f"Found folder: {name} (type: {folder_type})")
            
            return KeeperFolder(
                uid=uid,
                name=name,
                parent_uid=None,
                folder_type=folder_type
            )
            
        except Exception as e:
            logger.error(f"Failed to get folder {folder_uid}: {e}")
            import traceback
            traceback.print_exc()
        return None
    
    def grant_record_access(
        self,
        record_uid: str,
        user_email: str,
        permission: PermissionLevel,
        duration_seconds: Optional[int] = 86400
    ) -> Dict[str, Any]:
        """
        Grant access to a record with time limit using share-record command.
        """
        try:
            #Prevent granting access to record owner
            record_owner = self.get_record_owner(record_uid)

            if record_owner and user_email.lower() == record_owner.lower():
                return {
                    'success': False,
                    'error': (
                        f"Cannot grant access to record owner ({user_email}). "
                        f"The user already owns this record and has access to it."
                    )
                }
            
            if permission == PermissionLevel.CHANGE_OWNER:
                # Change owner command
                cmd_parts = ["share-record", record_uid, "-e", user_email, "-a", "owner", "--force"]
                
                # Execute command (no expiration for ownership transfer)
                response = self.session.post(
                    f'{self.base_url}/executecommand-async',
                    json={"command": " ".join(cmd_parts)},
                    timeout=10
                )
                
                if response.status_code != 202:
                    return {'success': False, 'error': f"Failed to submit command: HTTP {response.status_code}"}
                
                result = response.json()
                request_id = result.get('request_id')
                
                if not request_id:
                    return {'success': False, 'error': "No request_id received from API"}
                
                result_data = self._poll_for_result(request_id, max_wait=10)
                
                if not result_data:
                    return {'success': False, 'error': "Command timed out or failed"}
                
                if result_data.get('status') == 'success':
                    return {
                        'success': True,
                        'expires_at': 'N/A (Ownership Transfer)',
                        'permission': permission.value,
                        'duration': 'permanent'
                    }
                else:
                    error_msg = result_data.get('message', 'Unknown error')
                    if isinstance(error_msg, list):
                        error_msg = '\n'.join(error_msg)
                    return {'success': False, 'error': f"Failed to transfer ownership: {error_msg}"}
            
            # Map permission level to share-record flags
            permission_flags = []
            if permission == PermissionLevel.VIEW_ONLY:
                pass
            elif permission == PermissionLevel.CAN_EDIT:
                permission_flags.append("-w")
            elif permission == PermissionLevel.CAN_SHARE:
                permission_flags.append("-s")
            elif permission == PermissionLevel.EDIT_AND_SHARE:
                permission_flags.append("-w")
                permission_flags.append("-s")


            # To ensure clean permission replacement (especially for downgrades like Edit&Share -> Can Edit),
            # we first revoke existing access, then grant the new permission

            
            # Step 1: Revoke existing access
            revoke_cmd = f"share-record {record_uid} -e {user_email} -a revoke --force"
            
            try:
                revoke_response = self.session.post(
                    f'{self.base_url}/executecommand-async',
                    json={"command": revoke_cmd},
                    timeout=10
                )
                
                if revoke_response.status_code == 202:
                    revoke_result = revoke_response.json()
                    revoke_request_id = revoke_result.get('request_id')
                    if revoke_request_id:
                        # Wait for revoke to complete
                        revoke_result_data = self._poll_for_result(revoke_request_id, max_wait=5)
                        logger.debug(f"Revoke result: {revoke_result_data}")
            except Exception as e:
                # If revoke fails (e.g., user has no existing access), continue to grant
                logger.debug(f"Revoke failed or skipped: {e}")
            
            # Step 2: Grant new permission with clean state
            # Build command parts for grant
            cmd_parts = ["share-record", record_uid, "-e", user_email, "-a", "grant"]
            cmd_parts.extend(permission_flags)
            
            # Handle expiry based on permission type
            # Permanent-only permissions should not have expiry
            PERMANENT_ONLY_PERMISSIONS = [
                PermissionLevel.CAN_SHARE,
                PermissionLevel.EDIT_AND_SHARE,
                PermissionLevel.CHANGE_OWNER
            ]
            
            if permission in PERMANENT_ONLY_PERMISSIONS:
                # For permanent permissions, don't add expiry
                expires_at_str = "Never (Permanent)"
            elif duration_seconds is not None:
                # Add time-limited access for time-limited permissions
                expire_in = self._format_duration(duration_seconds)
                cmd_parts.extend(["--expire-in", expire_in])
                expires_at = datetime.now() + timedelta(seconds=duration_seconds)
                expires_at_str = expires_at.strftime('%Y-%m-%d %H:%M:%S')
            else:
                expires_at_str = "Never (Permanent)"
            
            # added --force to skip confirmation prompts
            cmd_parts.append("--force")
            command = " ".join(cmd_parts)

            response = self.session.post(
                f'{self.base_url}/executecommand-async',
                json={"command": command},
                timeout=10
            )
            
            if response.status_code != 202:
                return {
                    'success': False,
                    'error': f"Failed to submit command: HTTP {response.status_code}"
                }
            
            result = response.json()
            request_id = result.get('request_id')
            
            if not request_id:
                return {
                    'success': False,
                    'error': "No request_id received from API"
                }
            
            # Poll for result
            result_data = self._poll_for_result(request_id, max_wait=10)
            logger.debug(f"Result data: {result_data}")
            
            if not result_data:
                return {
                    'success': False,
                    'error': "Command timed out or failed"
                }
            
            if result_data.get('status') == 'success':
                # Check if this was an invitation (user not in vault yet)
                message = result_data.get('message', [])
                if isinstance(message, list):
                    message_text = ' '.join(message).lower()
                else:
                    message_text = str(message).lower()
                
                if 'invitation has been sent' in message_text or 'repeat this command when invitation is accepted' in message_text:
                    # Invitation sent - user doesn't exist in vault yet
                    logger.info(f"Share invitation sent to user (not in vault yet)")
                    return {
                        'success': True,
                        'invitation_sent': True,
                        'expires_at': 'Pending Invitation',
                        'permission': permission.value,
                        'duration': 'permanent',
                        'message': 'Share invitation sent. User must accept the invitation and create a Keeper account before they can access this record.'
                    }
                
                return {
                    'success': True,
                    'expires_at': expires_at_str,
                    'permission': permission.value,
                    'duration': 'temporary' if duration_seconds else 'permanent'
                }
            else:
                error_msg = result_data.get('message', result_data.get('error', 'Unknown error'))
                if isinstance(error_msg, list):
                    error_msg = '\n'.join(error_msg)
                

                error_lower = error_msg.lower()
                
                # Check for time-limited access conflict with share permissions
                if "time-limited access" in error_lower and "re-share" in error_lower:
                    return {
                        'success': False,
                        'error': "Unable to grant record access. This user already has temporary access to this record "
                                 "which conflicts with the selected permission level.\n\n"
                                 "First remove the user's existing access, then grant the new permission."
                    }
                
                # Check for existing share conflicts (e.g., Can Edit -> Can Share)
                if "already" in error_lower and ("shared" in error_lower or "access" in error_lower):
                    return {
                        'success': False,
                        'error': "Unable to update record access. This user already has existing permissions "
                                 "that conflict with the requested permission level.\n\n"
                                 "First revoke the user's existing access, then grant the new permission."
                    }
                
                # Check for permission type conflicts
                if "cannot" in error_lower and "permission" in error_lower:
                    return {
                        'success': False,
                        'error': "Unable to grant record access. The existing permission conflicts with the new permission.\n\n"
                                 "First revoke the user's existing access, then grant the new permission."
                    }
                
                return {
                    'success': False,
                    'error': f"Failed to grant access: {error_msg}"
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': f"Error granting record access: {str(e)}"
            }

    def _format_duration(self, seconds: int) -> str:
        """
        Convert seconds to Keeper share-record duration format.
        """
        if seconds < 3600:  # Less than 1 hour
            minutes = max(1, seconds // 60)
            return f"{minutes}mi"
        elif seconds < 86400:  # Less than 1 day
            hours = max(1, seconds // 3600)
            return f"{hours}h"
        elif seconds < 2592000:  # Less than 30 days
            days = max(1, seconds // 86400)
            return f"{days}d"
        elif seconds < 31536000:  # Less than 365 days
            months = max(1, seconds // 2592000)
            return f"{months}mo"
        else:  # 365+ days
            years = max(1, seconds // 31536000)
            return f"{years}y"
    
    def grant_folder_access(
        self,
        folder_uid: str,
        user_email: str,
        permission: PermissionLevel,
        duration_seconds: Optional[int] = 86400
    ) -> Dict[str, Any]:
        """
        Grant access to a folder with optional time limit using share-folder command.
        """
        try:
            # Map permission level to share-folder flags
            permission_flags = []
            
            if permission == PermissionLevel.NO_PERMISSIONS:
                # No user permissions: explicitly disable both manage permissions
                permission_flags.extend(["-o", "off", "-p", "off"])
            elif permission == PermissionLevel.MANAGE_USERS:
                # Can manage users
                permission_flags.extend(["-o", "on", "-p", "off"])
            elif permission == PermissionLevel.MANAGE_RECORDS:
                # Can manage records
                permission_flags.extend(["-o", "off", "-p", "on"])
            elif permission == PermissionLevel.MANAGE_ALL:
                # Can manage both users and records
                permission_flags.extend(["-o", "on", "-p", "on"])
            
            # Build command parts
            cmd_parts = ["share-folder", folder_uid, "-e", user_email, "-a", "grant"]
            cmd_parts.extend(permission_flags)
            
            # Add time-limited access if duration is specified
            if duration_seconds is not None:
                expire_in = self._format_duration(duration_seconds)
                cmd_parts.extend(["--expire-in", expire_in])
                expires_at = datetime.now() + timedelta(seconds=duration_seconds)
                expires_at_str = expires_at.strftime('%Y-%m-%d %H:%M:%S')
            else:
                expires_at_str = "Never (Permanent)"
            
            # Always add -f to force (skip confirmation prompts)
            cmd_parts.append("-f")
            
            # Build full command string
            command = " ".join(cmd_parts)
            
            # Execute command using async API
            response = self.session.post(
                f'{self.base_url}/executecommand-async',
                json={"command": command},
                timeout=10
            )
            
            if response.status_code != 202:
                return {
                    'success': False,
                    'error': f"Failed to submit command: HTTP {response.status_code}"
                }
            
            result = response.json()
            request_id = result.get('request_id')
            
            if not request_id:
                return {
                    'success': False,
                    'error': "No request_id received from API"
                }
            
            # Poll for result
            result_data = self._poll_for_result(request_id, max_wait=10)
            
            if not result_data:
                return {
                    'success': False,
                    'error': "Command timed out or failed"
                }
            

            if result_data.get('http_status') == 400:
                # Check if this is actually an invitation (comes as error for share-folder)
                error_field = result_data.get('error', '')
                error_lower = error_field.lower() if error_field else ''
                
                if 'invitation has been sent' in error_lower or 'repeat this command when invitation is accepted' in error_lower:
                    # Invitation sent - user doesn't exist in vault yet
                    logger.info(f"Share invitation sent to user (not in vault yet)")
                    return {
                        'success': True,
                        'invitation_sent': True,
                        'expires_at': 'Pending Invitation',
                        'permission': permission.value,
                        'duration': 'permanent',
                        'message': 'Share invitation sent. User must accept the invitation and create a Keeper account before they can access this folder.'
                    }
                
                if permission in [PermissionLevel.MANAGE_USERS, PermissionLevel.MANAGE_RECORDS, PermissionLevel.MANAGE_ALL]:
                    return {
                        'success': False,
                        'error': "Unable to grant folder access. This user already has temporary access to this folder "
                                 "which conflicts with the selected permission level.\n\n"
                                 "First remove the user's existing access, then grant the new permission."
                    }
                else:
                    return {
                        'success': False,
                        'error': "Unable to grant folder access. This user may have conflicting access to this folder.\n\n"
                                 "First remove the user's existing access, then grant the new permission."
                    }
            
            if result_data.get('status') == 'success':
                return {
                    'success': True,
                    'expires_at': expires_at_str,
                    'permission': permission.value,
                    'duration': 'temporary' if duration_seconds else 'permanent'
                }
            else:
                error_msg = result_data.get('message', result_data.get('error', 'Unknown error'))
                if isinstance(error_msg, list):
                    error_msg = '\n'.join(error_msg)
                
                # Check for time-limited access conflict with manage permissions
                # Also catch "User share...failed" errors which indicate permission conflicts
                is_time_limited_conflict = "time-limited access" in error_msg.lower() and ("manage" in error_msg.lower() or "re-share" in error_msg.lower())
                is_user_share_failed = "user share" in error_msg.lower() and "failed" in error_msg.lower()
                
                if is_time_limited_conflict or is_user_share_failed:
                    return {
                        'success': False,
                        'error': "Unable to grant folder access. This user already has temporary access to this folder "
                                 "which conflicts with the selected permission level.\n\n"
                                 "To fix: First remove the user's existing access, then grant the new permission."
                    }
                
                return {
                    'success': False,
                    'error': f"Failed to grant access: {error_msg}"
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': f"Error granting folder access: {str(e)}"
            }

    def _poll_for_result(self, request_id: str, max_wait: int = 15) -> Optional[Dict[str, Any]]:
        """
        Poll for async command result till got the result.
        """
        import time
        
        poll_interval = 0.5 
        max_poll_interval = 2.0 
        elapsed = 0
        
        while elapsed < max_wait:
            try:
                # Poll the result endpoint
                response = self.session.get(
                    f'{self.base_url}/result/{request_id}',
                    timeout=5
                )
                
                if response.status_code == 200:
                    result = response.json()
                    status = result.get('status')
                    
                    if status == 'success':
                        return result
                    elif status == 'error':
                        # Check both 'error' and 'message' fields
                        error_msg = result.get('error') or result.get('message', 'Unknown error')
                        logger.error(f"Command failed: {error_msg}")
                        return result
                    elif status in ['pending', 'running']:
                        # Still processing, continue polling
                        pass
                    else:
                        logger.warning(f"Unknown status: {status}")
                else:
                    if response.status_code == 202:
                        logger.debug("Async command still processing, waiting...")
                    else:
                        logger.warning(f"Poll returned status {response.status_code}")
                        try:
                            response_body = response.text
                            logger.debug(f"Poll response body: {response_body}")
                        except:
                            pass
                    if response.status_code == 400:
                        logger.error(f"Poll returned 400 - returning error immediately")
                        # Parse response body to include actual error message
                        try:
                            error_response = response.json()
                            error_response['http_status'] = 400
                            return error_response
                        except:
                            return {
                                'status': 'error',
                                'message': 'Command execution failed',
                                'http_status': 400
                            }
                
                # Wait before next poll
                time.sleep(poll_interval)
                elapsed += poll_interval
                poll_interval = min(poll_interval * 1.5, max_poll_interval)
                
            except Exception as e:
                logger.error(f"Error polling for result: {e}")
                return None
        
        logger.warning(f"Polling timed out after {max_wait} seconds")
        return None
    
    def _parse_search_records_results(self, result_data: Dict, limit: int) -> List[KeeperRecord]:
        """
        Parse search command results for records.
        """
        records = []
        
        try:
            # Check if data is directly in result_data or needs extraction
            data = result_data.get('data', [])
            
            if not isinstance(data, list):
                logger.debug(f"Unexpected data format: {type(data)}")
                return records
            
            logger.debug(f"Got {len(data)} records from search")
            
            for item in data:
                if not isinstance(item, dict):
                    continue
                
                # Extract fields from search response
                uid = item.get('uid', '')
                title = item.get('name', '')  # 'name' field contains the title
                record_type = 'login'  # Default type
                notes = ''
                
                # Parse details string: "Type: login, Description: bishal@gmail.com"
                details = item.get('details', '')
                if details:
                    parts = details.split(', ')
                    for part in parts:
                        if part.startswith('Type: '):
                            record_type = part.replace('Type: ', '').strip()
                        elif part.startswith('Description: '):
                            notes = part.replace('Description: ', '').strip()
                
                # Skip record type that contains "pam"
                if 'pam' in record_type.lower():
                    logger.debug(f"Skipping record {uid} with PAM type: {record_type}")
                    continue
                
                if uid and title:
                    records.append(KeeperRecord(
                        uid=uid,
                        title=title,
                        record_type=record_type,
                        notes=notes
                    ))
                    
                    if len(records) >= limit:
                        break
            
            return records
            
        except Exception as e:
            logger.error(f"Error parsing search records results: {e}")
            import traceback
            traceback.print_exc()
            return records
    
    def _parse_search_folders_results(self, result_data: Dict, limit: int) -> List[KeeperFolder]:
        """
        Parse search command results for shared folders.
        """
        folders = []
        
        try:
            # Check if data is directly in result_data or needs extraction
            data = result_data.get('data', [])
            
            if not isinstance(data, list):
                logger.debug(f"Unexpected data format: {type(data)}")
                return folders
            
            logger.debug(f"Got {len(data)} folders from search")
            
            for item in data:
                if not isinstance(item, dict):
                    continue
                
                # Extract fields from search response
                uid = item.get('uid', '')
                name = item.get('name', '')
                folder_type = item.get('type', 'shared_folder')
                
                if uid and name:
                    folders.append(KeeperFolder(
                        uid=uid,
                        name=name,
                        folder_type=folder_type
                    ))
                    
                    if len(folders) >= limit:
                        break
            
            return folders
            
        except Exception as e:
            logger.error(f"Error parsing search folders results: {e}")
            import traceback
            traceback.print_exc()
            return folders
    
    def create_one_time_share(
        self,
        record_uid: str,
        duration_seconds: Optional[int] = 86400,
        editable: bool = False
    ) -> Dict[str, Any]:
        """
        Create a one-time share link for a record.
        """
        try:
            # Format duration for Keeper Commander
            if duration_seconds is None:
                expire_in = "7d"  # Default: 7 days for permanent-like access
            else:
                expire_in = self._format_duration(duration_seconds)
            
            # Build command - use 'create' subcommand with -e flag and optional --editable
            editable_flag = " --editable" if editable else ""
            command = f"one-time-share create{editable_flag} {record_uid} -e {expire_in}"
            
            logger.debug(f"Creating one-time share: {command}")
            
            # Execute command using async API
            response = self.session.post(
                f'{self.base_url}/executecommand-async',
                json={"command": command},
                timeout=10
            )
            
            if response.status_code != 202:
                return {
                    'success': False,
                    'error': f"Failed to submit command: HTTP {response.status_code}"
                }
            
            result = response.json()
            request_id = result.get('request_id')
            
            if not request_id:
                return {
                    'success': False,
                    'error': "No request_id received from API"
                }
            
            # Poll for result
            result_data = self._poll_for_result(request_id, max_wait=30)
            
            if not result_data:
                return {
                    'success': False,
                    'error': "Command timed out or failed"
                }
            
            if result_data.get('status') == 'success':
                # Calculate expiration time
                if duration_seconds:
                    expires_at = datetime.now() + timedelta(seconds=duration_seconds)
                    expires_at_str = expires_at.strftime('%Y-%m-%d %H:%M:%S')
                else:
                    expires_at_str = "Never (7 days default)"
                
                # Extract share URL from response
                # Expected format from docs: "URL : https://keepersecurity.com/vault/share#..."
                share_url = None
                
                # Try structured fields first
                share_url = result_data.get('url') or result_data.get('share_url') or result_data.get('link')
                
                # If not found, parse from message output
                if not share_url and 'message' in result_data:
                    message = result_data.get('message')
                    
                    # Handle message as string (direct URL) - this is the common format
                    if isinstance(message, str):
                        # Check if the entire message is a URL
                        if message.startswith('http'):
                            share_url = message
                        else:
                            # Try to extract URL from text
                            url_match = re.search(r'https://[^\s]+', message)
                            if url_match:
                                share_url = url_match.group(0)
                    
                    # Handle message as list (array of strings)
                    elif isinstance(message, list):
                        for msg in message:
                            # Look for "URL : https://..." pattern from Keeper output
                            if 'URL' in str(msg) and 'https://' in str(msg):
                                url_match = re.search(r'https://keepersecurity\.com/vault/share[^\s]+', str(msg))
                                if url_match:
                                    share_url = url_match.group(0)
                                    break
                        
                        # If still not found, try generic URL extraction as fallback
                        if not share_url:
                            for msg in message:
                                if 'https://' in str(msg):
                                    url_match = re.search(r'(https://[^\s]+)', str(msg))
                                    if url_match:
                                        share_url = url_match.group(1)
                                        break
                
                if not share_url:
                    return {
                        'success': False,
                        'error': "Share link created but URL not found in response",
                        'raw_response': result_data
                    }
                
                return {
                    'success': True,
                    'share_url': share_url,
                    'expires_at': expires_at_str,
                    'duration': expire_in
                }
            else:
                error_msg = result_data.get('message', 'Unknown error')
                if isinstance(error_msg, list):
                    error_msg = '\n'.join(error_msg)
                return {
                    'success': False,
                    'error': f"Failed to create one-time share: {error_msg}"
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': f"Error creating one-time share: {str(e)}"
            }
    
    def create_record(
        self,
        title: str,
        login: Optional[str] = None,
        password: Optional[str] = None,
        url: Optional[str] = None,
        notes: Optional[str] = None,
        generate_password: bool = False,
        self_destruct_duration: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Create a new record in Keeper vault using the 'record-add' command.
        """
        try:
            # Build the record-add command
            command_parts = ["record-add"]
            
            # Add record type (lowercase, space-separated, no quotes)
            command_parts.append('--record-type login')
            command_parts.append(f"--title {shlex.quote(title)}")

            if notes:
                notes_for_cli = notes.replace('\n', '\\n')
                command_parts.append(f'--notes {shlex.quote(notes_for_cli)}')
            
            # Self-destruct (space-separated, no quotes on duration)
            if self_destruct_duration:
                command_parts.append(f'--self-destruct {self_destruct_duration}')

            if login:
                command_parts.append(f'login={shlex.quote(login)}')
            
            if password:
                command_parts.append(f'password={shlex.quote(password)}')
            elif generate_password:
                command_parts.append('password=$GEN')
            
            if url:
                command_parts.append(f'url={shlex.quote(url)}')
            
            command = " ".join(command_parts)

            response = self.session.post(
                f'{self.base_url}/executecommand-async',
                json={"command": command},
                timeout=10
            )
            
            if response.status_code != 202:
                return {
                    'success': False,
                    'error': f"Failed to submit command: HTTP {response.status_code}"
                }
            
            result = response.json()
            request_id = result.get('request_id')
            
            if not request_id:
                return {
                    'success': False,
                    'error': "No request_id received from API"
                }
            
            # Poll for result
            result_data = self._poll_for_result(request_id, max_wait=20)
            
            if not result_data:
                return {
                    'success': False,
                    'error': "Command timed out or failed"
                }
            
            if result_data.get('status') == 'success':
                # record-add doesn't return the UID, so we need to search for it
                logger.info("Record created successfully, searching for UID...")
                
                # Extract message for self-destruct URL (if applicable)
                message = result_data.get('message', '')
                if isinstance(message, list):
                    message = '\n'.join(message)
                
                # Search for the newly created record by exact title
                import time
                time.sleep(1)  
                
                try:
                    search_response = self.session.post(
                        f'{self.base_url}/executecommand-async',
                        json={"command": f'search {shlex.quote(title)} --format=json'},
                        timeout=10
                    )
                    
                    if search_response.status_code == 202:
                        search_request_id = search_response.json().get('request_id')
                        if search_request_id:
                            search_result = self._poll_for_result(search_request_id, max_wait=10)
                            
                            if search_result and search_result.get('status') == 'success':
                                # Parse search results
                                data = search_result.get('data', [])
                                if data and len(data) > 0:
                                    # Get the most recently created record (first match)
                                    newest_record = data[0]
                                    record_uid = newest_record.get('uid')
                                    
                                    if record_uid:
                                        generated_password = None
                                        if generate_password and not password:
                                            generated_password = "$GEN"
                                        return {
                                            'success': True,
                                            'record_uid': record_uid,
                                            'password': generated_password or password,
                                            'title': title,
                                            'self_destruct': bool(self_destruct_duration),
                                            'self_destruct_duration': self_destruct_duration
                                        }
                except Exception as search_error:
                    logger.error(f"Failed to search for created record: {search_error}")
                    logger.warning("Record created but UID not found via search")
                    return {
                        'success': False,
                        'error': "Record created but UID could not be retrieved. The record exists in your vault but the approval flow cannot continue automatically."
                    }
            else:
                error_msg = result_data.get('message', 'Unknown error')
                if isinstance(error_msg, list):
                    error_msg = '\n'.join(error_msg)
                return {
                    'success': False,
                    'error': f"Failed to create record: {error_msg}"
                }
                
        except Exception as e:
            logger.error(f"Exception in create_record: {e}")
            import traceback
            traceback.print_exc()
            return {
                'success': False,
                'error': f"Error creating record: {str(e)}"
            }
    
    def sync_pedm_data(self) -> bool:
        """
        Sync PEDM data from server.
        """
        try:
            response = self.session.post(
                f'{self.base_url}/executecommand-async',
                json={"command": "pedm sync-down"},
                timeout=10
            )
            
            if response.status_code != 202:
                logger.error(f"Failed to submit PEDM sync command: {response.status_code}")
                return False
            
            request_id = response.json().get('request_id')
            if not request_id:
                logger.error("No request_id received for PEDM sync")
                return False
            
            # Poll for result
            result_data = self._poll_for_result(request_id, max_wait=30)
            
            if not result_data:
                logger.warning("PEDM sync command timed out")
                return False
            
            status = result_data.get('status')
            if status == 'error':
                error_msg = result_data.get('message', 'Unknown error')
                logger.error(f"PEDM sync failed: {error_msg}")
                return False
            
            if status == 'success':
                logger.ok("PEDM data synced from server")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Exception syncing PEDM data: {e}")
            return False
    
    def get_pending_pedm_requests(self) -> Optional[List[Dict[str, Any]]]:
        """
        Get pending PEDM approval requests.
        """
        try:
            sync_success = self.sync_pedm_data()
            
            if not sync_success:
                logger.warning("PEDM sync failed, attempting to list anyway...")

            response = self.session.post(
                f'{self.base_url}/executecommand-async',
                json={"command": "pedm approval list --type pending --format=json"},
                timeout=10
            )
            
            if response.status_code != 202:
                logger.error(f"Failed to submit PEDM list command: {response.status_code}")
                return None
            
            request_id = response.json().get('request_id')
            if not request_id:
                logger.error("No request_id received for PEDM list")
                return None
            
            result_data = self._poll_for_result(request_id, max_wait=30)
            
            if not result_data:
                logger.warning("PEDM list command timed out")
                return None
            
            status = result_data.get('status')
            if status == 'error':
                error_msg = result_data.get('message', 'Unknown error')
                logger.error(f"PEDM command failed: {error_msg}")
                return None
            
            if status == 'success':
                data = result_data.get('data')
                
                # Handle None (no PEDM feature or no requests)
                if data is None:
                    logger.debug("No PEDM data returned (feature may not be enabled)")
                    return []
                
                if isinstance(data, list):
                    logger.debug(f"Retrieved {len(data)} pending PEDM request(s)")
                    return data
                else:
                    logger.error(f"Unexpected PEDM data type: {type(data)}")
                    return None
            
            return None 
            
        except Exception as e:
            logger.error(f"Exception fetching PEDM requests: {e}", exc_info=True)
            return None
    
    def approve_pedm_request(self, approval_uid: str) -> Dict[str, Any]:
        """
        Approve a PEDM request.
        """
        try:
            command = f"pedm approval action --approve {approval_uid}"
            
            response = self.session.post(
                f'{self.base_url}/executecommand-async',
                json={"command": command},
                timeout=10
            )
            
            if response.status_code != 202:
                return {'success': False, 'error': f"HTTP {response.status_code}"}
            
            request_id = response.json().get('request_id')
            if not request_id:
                return {'success': False, 'error': "No request_id"}
            
            result_data = self._poll_for_result(request_id, max_wait=10)
            
            if result_data and result_data.get('status') == 'success':
                return {'success': True}
            else:
                error = result_data.get('error') if result_data else None
                if not error:
                    error = result_data.get('message', 'Unknown error') if result_data else 'Timeout'
                
                # Check if this is the "already processed" error
                if error and ("does not exist or cannot be modified" in error or 
                              "Approval request does not exist" in error):
                    return {
                        'success': False, 
                        'error': error,
                        'already_processed': True
                    }
                
                return {'success': False, 'error': error}
                
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def deny_pedm_request(self, approval_uid: str) -> Dict[str, Any]:
        """
        Deny a PEDM request.
        """
        try:
            command = f"pedm approval action --deny {approval_uid}"
            logger.info(f"Denying PEDM request: {approval_uid}")
            
            response = self.session.post(
                f'{self.base_url}/executecommand-async',
                json={"command": command},
                timeout=10
            )
            
            if response.status_code != 202:
                return {'success': False, 'error': f"HTTP {response.status_code}"}
            
            request_id = response.json().get('request_id')
            if not request_id:
                return {'success': False, 'error': "No request_id"}
            
            result_data = self._poll_for_result(request_id, max_wait=10)
            
            if result_data and result_data.get('status') == 'success':
                return {'success': True}
            else:
                error = result_data.get('error') if result_data else None
                if not error:
                    error = result_data.get('message', 'Unknown error') if result_data else 'Timeout'
                
                # Check if this is the "already processed" error
                if error and ("does not exist or cannot be modified" in error or 
                              "Approval request does not exist" in error):
                    return {
                        'success': False, 
                        'error': error,
                        'already_processed': True
                    }
                
                return {'success': False, 'error': error}
                
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def get_pending_device_approvals(self) -> List[Dict[str, Any]]:
        """
        Get pending device approval requests.
        """
        try:
            response = self.session.post(
                f'{self.base_url}/executecommand-async',
                json={"command": "device-approve --reload --format=json"},
                timeout=10
            )
            
            if response.status_code != 202:
                logger.error(f"Failed to submit device-approve command: {response.status_code}")
                return []
            
            request_id = response.json().get('request_id')
            if not request_id:
                logger.error("No request_id received for device-approve")
                return []
            
            result_data = self._poll_for_result(request_id, max_wait=30)
            
            if not result_data:
                logger.warning("Device approval command timed out")
                return []
            
            status = result_data.get('status')
            if status == 'error':
                error_msg = result_data.get('message', 'Unknown error')
                logger.error(f"Device approval command failed: {error_msg}")
                return []
            
            if status == 'success':
                data = result_data.get('data')
                
                # Handle None (no pending device approvals)
                if data is None:
                    logger.debug("No pending device approvals")
                    return []
                
                if isinstance(data, list):
                    logger.debug(f"Retrieved {len(data)} pending device approval(s)")
                    return data
                else:
                    logger.error(f"Unexpected device approval data type: {type(data)}")
                    return []
            
            return []
            
        except Exception as e:
            logger.error(f"Exception fetching device approvals: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def approve_device(self, device_id: str) -> Dict[str, Any]:
        """
        Approve a device request.
        """
        try:
            command = f"device-approve --approve {device_id}"
            logger.info(f"Approving device: {device_id}")
            
            response = self.session.post(
                f'{self.base_url}/executecommand-async',
                json={"command": command},
                timeout=10
            )
            
            if response.status_code != 202:
                return {'success': False, 'error': f"HTTP {response.status_code}"}
            
            request_id = response.json().get('request_id')
            if not request_id:
                return {'success': False, 'error': "No request_id"}
            
            result_data = self._poll_for_result(request_id, max_wait=10)
            
            if result_data and result_data.get('status') == 'success':
                message = result_data.get('message', '')
                # Check if device was already handled (approved/denied elsewhere)
                if 'no pending devices' in message.lower():
                    logger.warning(f"Device {device_id} was already processed")
                    return {'success': False, 'already_handled': True, 'error': 'This device request was already processed'}
                logger.ok(f"Device {device_id} approved successfully")
                return {'success': True}
            else:
                error = result_data.get('message', 'Unknown error') if result_data else 'Timeout'
                return {'success': False, 'error': error}
                
        except Exception as e:
            logger.error(f"Exception approving device: {e}")
            return {'success': False, 'error': str(e)}
    
    def deny_device(self, device_id: str) -> Dict[str, Any]:
        """
        Deny a device request.
        """
        try:
            command = f"device-approve --deny {device_id}"
            logger.info(f"Denying device: {device_id}")
            
            response = self.session.post(
                f'{self.base_url}/executecommand-async',
                json={"command": command},
                timeout=10
            )
            
            if response.status_code != 202:
                return {'success': False, 'error': f"HTTP {response.status_code}"}
            
            request_id = response.json().get('request_id')
            if not request_id:
                return {'success': False, 'error': "No request_id"}
            
            result_data = self._poll_for_result(request_id, max_wait=10)
            
            if result_data and result_data.get('status') == 'success':
                message = result_data.get('message', '')
                # Check if device was already handled (approved/denied elsewhere)
                if 'no pending devices' in message.lower():
                    logger.warning(f"Device {device_id} was already processed")
                    return {'success': False, 'already_handled': True, 'error': 'This device request was already processed'}
                logger.ok(f"Device {device_id} denied successfully")
                return {'success': True}
            else:
                error = result_data.get('message', 'Unknown error') if result_data else 'Timeout'
                return {'success': False, 'error': error}
                
        except Exception as e:
            logger.error(f"Exception denying device: {e}")
            return {'success': False, 'error': str(e)}
