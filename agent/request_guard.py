"""Catch exact predicates that must not be silently generalized by the planner.

This is a narrow semantic guard, not a replacement for the query compiler. The
compiler remains the authority for every field and filter the model submits.
"""
from __future__ import annotations

import re
from .policy import AccessContext, AccessDenied

_EXACT_ZIP = re.compile(r"\b(?:zip(?:\s+code)?|postal\s+code)\s*(?:is|=|of|in|:)?\s*\d{5}(?:-\d{4})?\b", re.I)
_INCOME_TOPIC = re.compile(r"\b(?:earn\w*|income|salary|make\w*|paid)\b", re.I)
_THRESHOLD = re.compile(r"\b(?:more than|greater than|less than|at least|at most|above|below|over|under|exceed\w*|between)\s*\$?\s*\d[\d,]*(?:\.\d+)?\b", re.I)


def check(question: str, context: AccessContext) -> None:
    if context.role != 'analyst':
        return
    if _EXACT_ZIP.search(question):
        raise AccessDenied(
            'Selecting customers by an exact ZIP code requires a field outside your access. '
            'You may ask for a ZIP prefix without treating it as the exact ZIP.',
            'precise_predicate_denied',
        )
    if _INCOME_TOPIC.search(question) and _THRESHOLD.search(question):
        raise AccessDenied(
            'Selecting customers by an exact income threshold requires a field outside your access. '
            'You may ask for income bands instead.',
            'precise_predicate_denied',
        )
