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
Approver-side *catalog view* for team-scoped searches.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Iterable, List, Optional, Set

from .logger import logger


_MAX_WORKERS = 8


def is_catalog_mode(scope: Optional[Set[str]]) -> bool:
    """
    Should the caller render a catalog (as opposed to running a Commander
    search) for this kind?
    """
    return isinstance(scope, set) and len(scope) > 0


def _hydrate_kind(
    keeper_client,
    uids: Iterable[str],
    getter_name: str,
    kind_label: str,
) -> List[Any]:
    """
    Fetch each UID in parallel via ``getter_name`` on ``keeper_client``.
    Silently drops UIDs that come back ``None`` (deleted / no access), with
    a single WARN log listing the missing UIDs so admins notice drift.
    """
    seen = set()
    uid_list: List[str] = []
    for raw in uids:
        u = str(raw or "").strip()
        if u and u not in seen:
            seen.add(u)
            uid_list.append(u)
    if not uid_list:
        return []

    fetch = getattr(keeper_client, getter_name, None)
    if not callable(fetch):
        logger.error(
            f"Catalog: keeper_client is missing {getter_name!r}; "
            f"cannot hydrate {kind_label}s"
        )
        return []

    results: List[Any] = []
    missing: List[str] = []

    def _one(uid: str):
        try:
            return uid, fetch(uid)
        except Exception as e:
            logger.warning(f"Catalog: failed to fetch {kind_label} {uid}: {e}")
            return uid, None

    workers = min(_MAX_WORKERS, len(uid_list))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_one, uid) for uid in uid_list]
        for fut in as_completed(futures):
            uid, item = fut.result()
            if item is None:
                missing.append(uid)
            else:
                results.append(item)

    if missing:
        logger.warning(
            f"Catalog: skipping {len(missing)} unavailable {kind_label} "
            f"UID(s) (deleted or no access): {missing}"
        )

    def _sort_key(item: Any) -> str:
        for attr in ("title", "name"):
            value = getattr(item, attr, None)
            if value:
                return str(value).lower()
        return ""

    results.sort(key=_sort_key)
    return results


def hydrate_records(keeper_client, uids: Iterable[str]) -> List[Any]:
    """Hydrate the scoped record UIDs into ``KeeperRecord`` objects."""
    return _hydrate_kind(keeper_client, uids, "get_record_by_uid", "record")


def hydrate_folders(keeper_client, uids: Iterable[str]) -> List[Any]:
    """Hydrate the scoped folder UIDs into ``KeeperFolder`` objects."""
    return _hydrate_kind(keeper_client, uids, "get_folder_by_uid", "folder")


def filter_items(items: List[Any], query: str) -> List[Any]:
    """
    Client-side substring filter over an already-hydrated catalog.

    * Empty query -> full list (preserves catalog ordering).
    * Match tests ``title`` then ``name`` (records vs folders), case-insensitive.
    """
    q = (query or "").strip().lower()
    if not q:
        return list(items)

    def _match(item: Any) -> bool:
        for attr in ("title", "name"):
            v = getattr(item, attr, None)
            if v and q in str(v).lower():
                return True
        return False

    return [i for i in items if _match(i)]


def _apply_ots_filter(records: List[Any]) -> List[Any]:
    """
    Mirror the OTS-time filter that ``_parse_search_records_results`` applies
    to normal search hits: one-time-share can't operate on PAM records or
    Nested Share Folder records, so they are hidden from catalog too. Keeps
    catalog + OTS composable even if an admin misconfigures scope UIDs.
    """
    from .utils import is_pam_record_type

    kept: List[Any] = []
    for r in records:
        record_type = getattr(r, "record_type", "") or ""
        if is_pam_record_type(record_type):
            logger.debug(
                f"Catalog OTS: skipping {getattr(r, 'uid', '?')} "
                f"(PAM type {record_type!r})"
            )
            continue
        if bool(getattr(r, "is_nsf", False)):
            logger.debug(
                f"Catalog OTS: skipping {getattr(r, 'uid', '?')} (NSF)"
            )
            continue
        kept.append(r)
    return kept


def maybe_catalog_fetch(
    config,
    keeper_client,
    client,
    user_id: str,
    search_type: str,
    query: str,
    approval_data: dict,
    for_one_time_share: bool = False,
) -> Optional[List[Any]]:
    """
    Single entry point used by every catalog-aware call site.
    """
    from .approver_boundary import resolve_allowed_scope

    folder_scope, record_scope = resolve_allowed_scope(
        config, keeper_client, client, user_id,
        channel_id=approval_data.get("channel_id"),
    )
    scope = record_scope if search_type == "record" else folder_scope

    if not is_catalog_mode(scope):
        approval_data.pop("catalog_mode", None)
        approval_data.pop("scope_size", None)
        return None

    if search_type == "record":
        items = hydrate_records(keeper_client, scope)
        if for_one_time_share:
            items = _apply_ots_filter(items)
    else:
        items = hydrate_folders(keeper_client, scope)

    approval_data["catalog_mode"] = True
    approval_data["scope_size"] = len(scope)
    logger.info(
        f"Catalog: {search_type} scope={len(scope)} -> "
        f"{len(items)} item(s) hydrated"
    )
    return filter_items(items, query)
