"""Strict supplied LDAP search allocation; absence exposes labelled cached data."""

import json

from keep.identity.selection import ConfiguredDirectorySearch
from keep.identity.worker import load_directory_config


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Directory search profile contains a duplicate field")
        result[key] = value
    return result


def configured_search(settings):
    if not settings.directory_search_profile:
        return None
    if not settings.directory_config:
        raise ValueError("Directory search requires an explicit directory binding")
    path = settings.directory_search_profile
    if path.stat().st_size > 65536:
        raise ValueError("Directory search profile exceeds size limit")
    document = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object)
    if not isinstance(document, dict) or set(document) != {
        "qualified",
        "max_seconds",
        "max_matches",
        "max_pages",
    }:
        raise ValueError("Explicit qualified directory search allocation required")
    return ConfiguredDirectorySearch(load_directory_config(settings.directory_config), **document)
