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
Team-based boundary / scope enforcement for approver search.
"""

from typing import Any, Dict, List, Optional, Set, Tuple

from .logger import logger
from .utils import get_user_email_from_slack


def _boundary_data(config) -> Dict[str, Any]:
    """Return the raw ``multichannel_approver`` config block (never None)."""
    try:
        return config.get('multichannel_approver', {}) or {}
    except Exception:
        return {}


def is_boundary_enabled(config) -> bool:
    """
    Master gate: scope filtering only runs when multi-channel approver is
    enabled. The per-team / per-kind UID lists then decide what is actually
    restricted (see ``resolve_allowed_scope``).
    """
    return bool(_boundary_data(config).get('enabled', False))


def _teams(config) -> List[Dict[str, Any]]:
    data = _boundary_data(config)
    teams = data.get('teams', []) or []
    return [t for t in teams if isinstance(t, dict)]


def _any_scope_configured(teams_cfg: List[Dict[str, Any]]) -> bool:
    """
    True when at least one team declares any allowed folder/record UID.

    Used to distinguish "routing-only" mode (no team has scope) from "scoping
    active" mode. 
    """
    for t in teams_cfg:
        if (t.get('allowed_folder_uids') or []) or (t.get('allowed_record_uids') or []):
            return True
    return False


def _scope_from_team_entry(team: Dict[str, Any]) -> Tuple[Optional[Set[str]], Optional[Set[str]]]:
    """
    Build per-kind scope sets from one team's UID lists.

    Empty list for a kind -> ``None`` (unrestricted for that kind).
  Non-empty -> ``set`` of UIDs.
    """
    folder_scope: Set[str] = set()
    record_scope: Set[str] = set()
    for uid in (team.get('allowed_folder_uids', []) or []):
        if uid:
            folder_scope.add(str(uid).strip())
    for uid in (team.get('allowed_record_uids', []) or []):
        if uid:
            record_scope.add(str(uid).strip())
    return folder_scope or None, record_scope or None


def _team_for_channel(
    teams_cfg: List[Dict[str, Any]], channel_id: str,
) -> Optional[Dict[str, Any]]:
    """Return the approval-team config row whose ``channel_id`` matches."""
    target = str(channel_id or '').strip()
    if not target:
        return None
    for team in teams_cfg:
        if str(team.get('channel_id', '')).strip() == target:
            return team
    return None


def resolve_allowed_scope(
    config,
    keeper_client,
    client,
    user_id: str,
    channel_id: Optional[str] = None,
) -> Tuple[Optional[Set[str]], Optional[Set[str]]]:
    """
    Resolve folder/record UID scope for an approver search.
    """
    if not is_boundary_enabled(config):
        return None, None

    teams_cfg = _teams(config)

    # Routing-only mode: multichannel is enabled but no team has any UID
    # configured anywhere. In that case the feature is just team-based routing
    # and there is nothing to filter -- don't restrict any approver, even
    # ones outside every approval team.
    if not _any_scope_configured(teams_cfg):
        logger.debug(
            "Boundary: no UIDs configured on any team; routing-only mode -> "
            "no restriction"
        )
        return None, None

    channel_id = str(channel_id or '').strip()
    if channel_id:
        try:
            default_channel = str(config.slack.approvals_channel_id).strip()
        except Exception:
            default_channel = ''

        if default_channel and channel_id == default_channel:
            logger.info(
                f"Boundary: default approval channel {channel_id}; "
                f"no scope (traditional search)"
            )
            return None, None

        team_for_channel = _team_for_channel(teams_cfg, channel_id)
        if team_for_channel is not None:
            folder_result, record_result = _scope_from_team_entry(team_for_channel)
            team_name = str(team_for_channel.get('name', '')).strip() or '<unnamed>'
            logger.info(
                f"Boundary: channel {channel_id} -> team '{team_name}' -> "
                f"folders={'ALL' if folder_result is None else len(folder_result)}, "
                f"records={'ALL' if record_result is None else len(record_result)}"
            )
            return folder_result, record_result

    # Fallback: scope by the searching approver's Keeper team membership
    # (used when channel_id is missing or does not match a known team channel).
    try:
        email = get_user_email_from_slack(client, user_id)
        user_teams = set(keeper_client.get_user_teams(email))

        folder_scope: Set[str] = set()
        record_scope: Set[str] = set()
        matched_any = False
        for team in teams_cfg:
            if str(team.get('name', '')).strip() not in user_teams:
                continue
            matched_any = True
            for uid in (team.get('allowed_folder_uids', []) or []):
                if uid:
                    folder_scope.add(str(uid).strip())
            for uid in (team.get('allowed_record_uids', []) or []):
                if uid:
                    record_scope.add(str(uid).strip())

        if not matched_any:
            logger.info(
                f"Boundary: {email} in no approval team {sorted(user_teams)}; "
                f"deny (empty scope)"
            )
            return set(), set()

        folder_result: Optional[Set[str]] = folder_scope or None
        record_result: Optional[Set[str]] = record_scope or None

        logger.info(
            f"Boundary: {email} -> teams {sorted(user_teams)} -> "
            f"folders={'ALL' if folder_result is None else len(folder_result)}, "
            f"records={'ALL' if record_result is None else len(record_result)}"
        )
        return folder_result, record_result
    except Exception as e:
        logger.error(
            f"Boundary: error resolving scope for {user_id}: {e}; deny (empty scope)"
        )
        return set(), set()


def _filter_by_uid(results: List[Any], allowed_uids: Optional[Set[str]]) -> List[Any]:
    """
    Keep only results whose ``.uid`` is in ``allowed_uids``.

    ``allowed_uids is None`` => no restriction (boundary off): return as-is.
    """
    if allowed_uids is None:
        return results
    filtered = [r for r in results if getattr(r, 'uid', None) in allowed_uids]
    if len(filtered) != len(results):
        logger.debug(
            f"Boundary: filtered search results {len(results)} -> {len(filtered)}"
        )
    return filtered


def filter_records(results: List[Any], allowed_record_uids: Optional[Set[str]]) -> List[Any]:
    """Filter record search results to the approver's allowed record UIDs."""
    return _filter_by_uid(results, allowed_record_uids)


def filter_folders(results: List[Any], allowed_folder_uids: Optional[Set[str]]) -> List[Any]:
    """Filter folder search results to the approver's allowed folder UIDs."""
    return _filter_by_uid(results, allowed_folder_uids)
