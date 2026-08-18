"""Filtering and paging helpers shared by every list-shaped tool.

Kept separate because they are pure functions over lists: the exhaustive
boundary tests live against this module rather than against tools that need a
Ghidra subprocess.
"""

from typing import Callable, Sequence, TypeVar

T = TypeVar("T")


def substring_filter(
    items: Sequence[T], needle: str | None, key: Callable[[T], str]
) -> list[T]:
    """Case-insensitive substring match. A None or empty needle matches all."""
    if not needle:
        return list(items)
    lowered = needle.lower()
    return [item for item in items if lowered in key(item).lower()]


def page(items: Sequence[T], limit: int, offset: int) -> list[T]:
    """Slice a result set defensively.

    Negative offsets clamp to 0 rather than wrapping around from the end, which
    is what a bare Python slice would do and would silently return the wrong
    rows. A limit of 0 returns nothing; a negative limit is treated as 0.
    """
    start = max(0, offset)
    if limit <= 0:
        return []
    return list(items[start : start + limit])
