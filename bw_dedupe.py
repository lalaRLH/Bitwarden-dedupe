#!/usr/bin/env python3
"""
Bitwarden JSON Export Deduplicator & Merger
============================================
Merges duplicate login entries, combining fields like passwords,
passkeys, URIs, notes, custom fields, and TOTP across duplicates.

Usage:
    python3 bw_dedupe.py <input.json> [output.json]

If no output file is specified, output is written to:
    <input>_deduped.json
"""

import json
import sys
import re
import copy
from collections import defaultdict
from pathlib import Path


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def normalise_uri(uri: str) -> str:
    """Strip scheme, www., trailing slashes for grouping purposes."""
    uri = uri.lower().strip()
    uri = re.sub(r'^https?://', '', uri)
    uri = re.sub(r'^www\.', '', uri)
    uri = uri.rstrip('/')
    # Drop query strings and fragments for grouping
    uri = re.sub(r'[?#].*$', '', uri)
    return uri


def primary_uri(item: dict) -> str:
    """Return the first URI from a login item, normalised."""
    uris = (item.get('login') or {}).get('uris') or []
    if uris:
        return normalise_uri(uris[0].get('uri') or '')
    return ''


def login_username(item: dict) -> str:
    return ((item.get('login') or {}).get('username') or '').strip().lower()


def make_group_key(item: dict) -> tuple:
    """
    Group key: (type, primary_uri, username).
    Falls back to (type, name, username) when there's no URI.
    """
    if item.get('type') == 1:  # login
        uri = primary_uri(item)
        user = login_username(item)
        if uri:
            return (1, uri, user)
        # No URI — group by normalised name + username
        return (1, '__nourl__', item.get('name', '').strip().lower(), user)
    # Non-login items: group by type + exact name (conservative)
    return (item.get('type', 0), item.get('name', '').strip().lower())


# ---------------------------------------------------------------------------
# Field mergers
# ---------------------------------------------------------------------------

def pick_nonempty(*values):
    """Return the first non-empty value."""
    for v in values:
        if v:
            return v
    return values[-1] if values else None


def merge_uris(base_uris: list, other_uris: list) -> list:
    """Union of URI lists, deduped by normalised URI string."""
    seen = {}
    for u in (base_uris or []) + (other_uris or []):
        key = normalise_uri(u.get('uri') or '')
        if key and key not in seen:
            seen[key] = u
    return list(seen.values())


def merge_fields(base_fields: list, other_fields: list) -> list:
    """
    Merge custom fields. Fields with the same name are kept once;
    prefer non-empty values.
    """
    combined = {}
    for f in (base_fields or []) + (other_fields or []):
        name = (f.get('name') or '').strip()
        if name not in combined or (not combined[name].get('value') and f.get('value')):
            combined[name] = f
    return list(combined.values())


def merge_notes(a: str, b: str) -> str:
    """Concatenate distinct, non-empty notes."""
    a = (a or '').strip()
    b = (b or '').strip()
    if not a:
        return b
    if not b or b == a:
        return a
    return f"{a}\n\n---\n\n{b}"


def merge_fido_credentials(base: list, other: list) -> list:
    """Union passkeys/FIDO2 credentials by credentialId."""
    seen = {}
    for cred in (base or []) + (other or []):
        cid = cred.get('credentialId') or json.dumps(cred, sort_keys=True)
        if cid not in seen:
            seen[cid] = cred
    return list(seen.values())


def merge_login(base_login: dict, other_login: dict) -> dict:
    """Merge two login sub-objects."""
    merged = copy.deepcopy(base_login)

    merged['username'] = pick_nonempty(
        base_login.get('username'), other_login.get('username'), '')
    merged['password'] = pick_nonempty(
        base_login.get('password'), other_login.get('password'), '')
    merged['totp'] = pick_nonempty(
        base_login.get('totp'), other_login.get('totp'), '')

    merged['uris'] = merge_uris(
        base_login.get('uris'), other_login.get('uris'))

    # Passkeys / FIDO2 credentials
    base_fido = base_login.get('fido2Credentials') or []
    other_fido = other_login.get('fido2Credentials') or []
    merged['fido2Credentials'] = merge_fido_credentials(base_fido, other_fido)

    return merged


def merge_items(base: dict, other: dict) -> dict:
    """Merge `other` into `base`, returning a new merged item."""
    merged = copy.deepcopy(base)

    # Prefer non-empty name
    merged['name'] = pick_nonempty(base.get('name'), other.get('name'), '')

    # Notes
    merged['notes'] = merge_notes(base.get('notes'), other.get('notes'))

    # Favourite: either being favourite keeps it
    merged['favorite'] = base.get('favorite') or other.get('favorite') or False

    # Custom fields
    merged['fields'] = merge_fields(base.get('fields'), other.get('fields'))

    # Login-specific
    if base.get('type') == 1 and other.get('type') == 1:
        merged['login'] = merge_login(
            base.get('login') or {}, other.get('login') or {})

    # Password history: union
    base_hist = base.get('passwordHistory') or []
    other_hist = other.get('passwordHistory') or []
    seen_pws = {h.get('password') for h in base_hist}
    for h in other_hist:
        if h.get('password') not in seen_pws:
            base_hist.append(h)
            seen_pws.add(h.get('password'))
    merged['passwordHistory'] = base_hist

    return merged


# ---------------------------------------------------------------------------
# Main dedup logic
# ---------------------------------------------------------------------------

def deduplicate(data: dict) -> tuple[dict, dict]:
    items = data.get('items', [])

    groups: dict[tuple, list] = defaultdict(list)
    non_login_pass_through = []

    for item in items:
        key = make_group_key(item)
        groups[key].append(item)

    merged_items = []
    stats = {'total_in': len(items), 'groups': 0,
             'merged': 0, 'kept_as_is': 0}

    for key, group in groups.items():
        stats['groups'] += 1
        if len(group) == 1:
            merged_items.append(group[0])
            stats['kept_as_is'] += 1
        else:
            # Sort: prefer items with passwords / more fields first as base
            def item_score(it):
                login = it.get('login') or {}
                return (
                    bool(login.get('password')),
                    bool(login.get('fido2Credentials')),
                    bool(login.get('totp')),
                    bool(it.get('notes')),
                    len(it.get('fields') or []),
                    len(login.get('uris') or []),
                )
            group.sort(key=item_score, reverse=True)

            base = group[0]
            for other in group[1:]:
                base = merge_items(base, other)
                stats['merged'] += 1

            merged_items.append(base)

    result = copy.deepcopy(data)
    result['items'] = merged_items
    stats['total_out'] = len(merged_items)
    return result, stats


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    input_path = Path(sys.argv[1])
    if not input_path.exists():
        print(f"Error: file not found: {input_path}")
        sys.exit(1)

    if len(sys.argv) >= 3:
        output_path = Path(sys.argv[2])
    else:
        output_path = input_path.with_name(
            input_path.stem + '_deduped' + input_path.suffix)

    print(f"Reading  : {input_path}")
    with open(input_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    result, stats = deduplicate(data)

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    print(f"Writing  : {output_path}")
    print()
    print("── Summary ─────────────────────────────")
    print(f"  Items in        : {stats['total_in']}")
    print(f"  Unique groups   : {stats['groups']}")
    print(f"  Items merged    : {stats['merged']}")
    print(f"  Items kept as-is: {stats['kept_as_is']}")
    print(f"  Items out       : {stats['total_out']}")
    duplicates_removed = stats['total_in'] - stats['total_out']
    print(f"  Duplicates axed : {duplicates_removed}")
    print("────────────────────────────────────────")


if __name__ == '__main__':
    main()
