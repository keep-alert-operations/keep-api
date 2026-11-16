"""ADAPI picker search (REV-73), built once in the Product API lifespan.

Requirements: REV-73; tenant access 5 (search, search cache); plan A11, A14, A19.

A search asks ADAPI ``/users`` and ``/groups`` with ``samAccountName=*term*`` and
``customFilter=(displayName=*term*)`` (the two parameters are OR'ed), with no
security-group filter. In ``customFilter`` the term is escaped per RFC 4515, so
``( ) * \\`` arrive as ``\\28 \\29 \\2a \\5c`` and the term stays literal. A term
holding a character no sAMAccountName can contain (or a parenthesis) is sent as
the display-name filter only, because ADAPI's own handling of the
``samAccountName`` parameter is unknown and ``*`` there is a wildcard. ADAPI
caps an answer silently at 1,000 rows; such an answer is reported so the picker
asks the user to type more. Answers may come from the Redis search cache.
"""

from __future__ import annotations

import threading
import unicodedata
from dataclasses import dataclass
from typing import Any

import httpx

from keep.identity.adapi import (
    FORBIDDEN_CHARACTERS,
    GROUP_ATTRIBUTES,
    REQUEST_CALL_CAP,
    USER_ATTRIBUTES,
    ADAPIClient,
    ADAPIConfig,
    InvalidUsername,
    attribute_params,
    escape_filter_value,
    group_object,
    normalize_username,
    user_object,
)
from keep.identity.directory import DirectoryObject, DirectoryUnavailable
from keep.identity.search_cache import CachedAnswer, SearchCache

# ADAPI's silent cap on one search answer.
SEARCH_CAP = 1000
KINDS = ("user", "team")


@dataclass(frozen=True)
class SearchAnswer:
    """Picker matches from ADAPI (or the search cache) for one term.

    ``capped``: an ADAPI answer hit the 1,000-row cap, so the user should type more.
    ``cached``: at least one of the two answers came from the search cache.
    """

    objects: tuple[DirectoryObject, ...]
    capped: bool
    cached: bool


def normalize_term(term: str) -> str:
    """The form searched and cached: NFC, trimmed, lowercase (AD matching ignores case)."""
    return unicodedata.normalize("NFC", term).strip().lower()


def _sam_searchable(term: str) -> bool:
    return not any(
        ch in FORBIDDEN_CHARACTERS or ch in "()" or unicodedata.category(ch).startswith("C")
        for ch in term
    )


def search_params(kind: str, term: str) -> list[tuple[str, str]]:
    """The OR'ed ADAPI parameters of one picker search (``term`` already normalized)."""
    params = [("samAccountName", f"*{term}*")] if _sam_searchable(term) else []
    params.append(("customFilter", f"(displayName=*{escape_filter_value(term)}*)"))
    params.extend(attribute_params(USER_ATTRIBUTES if kind == "user" else GROUP_ATTRIBUTES))
    return params


def _objects(source: str, kind: str, rows) -> list[DirectoryObject]:
    """Rows Keep can show: parseable, not computer accounts, valid usernames."""
    result = []
    for row in rows:
        try:
            obj = (user_object if kind == "user" else group_object)(source, row)
        except DirectoryUnavailable:
            continue
        name = obj.key.object_id
        try:
            if name.endswith("$") or normalize_username(name) != name:
                continue
        except InvalidUsername:
            continue
        result.append(obj)
    return result


class ADAPISearch:
    """``search(term) -> SearchAnswer``; raises DirectoryUnavailable when ADAPI fails.

    Thread-safe: each search that needs ADAPI uses its own short-lived client.
    ``cache`` (optional) holds raw answers; ``transport`` is for tests.
    """

    def __init__(
        self,
        config: ADAPIConfig,
        *,
        cache: SearchCache | None = None,
        call_cap: float = REQUEST_CALL_CAP,
        transport: httpx.BaseTransport | None = None,
        stop: threading.Event | None = None,
    ):
        self.config, self.cache, self.call_cap = config, cache, call_cap
        self.transport, self.stop = transport, stop

    def _answer(self, client_holder: list, kind: str, term: str) -> tuple[CachedAnswer, bool]:
        if self.cache is not None:
            hit = self.cache.get(kind, term)
            if hit is not None:
                return hit, True
        if not client_holder:
            client_holder.append(
                ADAPIClient(
                    self.config, call_cap=self.call_cap, stop=self.stop, transport=self.transport
                )
            )
        client = client_holder[0]
        params = search_params(kind, term)
        rows = client.find_users(params) if kind == "user" else client.find_groups(params)
        answer = CachedAnswer(tuple(rows), len(rows) >= SEARCH_CAP)
        if self.cache is not None:
            self.cache.put(kind, term, answer)
        return answer, False

    def __call__(self, term: str) -> SearchAnswer:
        term = normalize_term(term)
        holder: list[ADAPIClient] = []
        try:
            answers = {kind: self._answer(holder, kind, term) for kind in KINDS}
        finally:
            for client in holder:
                client.close()
        seen, objects = set(), []
        for kind in KINDS:
            for obj in _objects(self.config.source, kind, answers[kind][0].rows):
                if obj.key not in seen:
                    seen.add(obj.key)
                    objects.append(obj)
        return SearchAnswer(
            tuple(objects),
            any(answer.capped for answer, _ in answers.values()),
            any(cached for _, cached in answers.values()),
        )


def configured_search(
    settings: Any,
    cache: SearchCache | None = None,
    *,
    transport: httpx.BaseTransport | None = None,
) -> ADAPISearch | None:
    """The picker search over ``KEEP_ADAPI_URL``, or None without ADAPI settings.

    Without it, pickers list Keep's saved principals only (labelled as cached).
    """
    if not settings.adapi_url or settings.adapi_client_id is None:
        return None
    return ADAPISearch(ADAPIConfig.from_settings(settings), cache=cache, transport=transport)
