import re
from typing import TypeVar


class CounterMixin:
    cnt: int = 0

    def count(self, amount: int = 1):
        self.cnt += amount


def match(arr: list[str | re.Pattern], item: str) -> bool:
    """Match a string against a list of strings or regex patterns."""
    for pat in arr:
        if isinstance(pat, str):
            if item == pat:
                return True
        else:
            if pat.match(item):
                return True
    return False


T = TypeVar("T")


def match_dict(patterns: dict[str | re.Pattern, T], item: str) -> T | None:
    """match a string against a dictionary of strings or regex patterns, Returns the value if matched."""
    for pat, val in patterns.items():
        if isinstance(pat, str):
            if item == pat:
                return val
        else:
            if pat.match(item):
                return val
    return None
