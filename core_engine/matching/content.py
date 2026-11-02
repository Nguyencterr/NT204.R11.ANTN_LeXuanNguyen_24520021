"""Assignment 3, section 4.4: content matching with sticky modifiers.

Semantics implemented and documented in the README:

* ``offset``/``depth`` are absolute: search ``[offset, offset + depth)``.
  ``offset`` defaults to 0 and ``depth`` defaults to the rest of the buffer.
* ``distance``/``within`` are relative to the end of the previous content
  match in the *same* buffer: search
  ``[prev_end + distance, prev_end + distance + within)``.
* A content sequence is searched inside one buffer only; buffers are never
  concatenated.
* When the first occurrence of a content cannot lead to a complete sequence,
  the matcher backtracks and tries the next occurrence (required by the
  assignment brief).

Only ASCII case folding is used for ``nocase`` (``bytes.lower()``), so byte
positions stay exact for UTF-8 payloads.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterator

from ..rule_parser.models import ContentCondition


@dataclass(frozen=True)
class ContentMatch:
    """One content occurrence inside one buffer."""

    condition_index: int
    content: str
    buffer: str
    position: int
    end: int
    nocase: bool
    window_start: int
    window_end: int

    def to_dict(self) -> dict[str, Any]:

        return {
            "condition_index": self.condition_index,
            "content": self.content,
            "buffer": self.buffer,
            "position": self.position,
            "end": self.end,
            "nocase": self.nocase,
            "window_start": self.window_start,
            "window_end": self.window_end,
        }


@dataclass(frozen=True)
class ContentMatchOutcome:
    """Result of matching every content condition of one rule."""

    matched: bool
    buffer: str | None = None
    matches: tuple[ContentMatch, ...] = field(default_factory=tuple)
    reason: str | None = None
    buffers_considered: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:

        return {
            "matched": self.matched,
            "buffer": self.buffer,
            "matches": [match.to_dict() for match in self.matches],
            "reason": self.reason,
            "buffers_considered": list(self.buffers_considered),
        }


def _window(
    condition: ContentCondition,
    data_length: int,
    previous_end: int | None,
) -> tuple[int, int]:
    """Return the clamped ``[start, end)`` search window for a condition."""

    if condition.is_relative:

        base = previous_end if previous_end is not None else 0
        start = base + (condition.distance or 0)

        if condition.within is not None:

            end = start + condition.within

        else:

            end = data_length

    else:

        start = condition.offset or 0

        if condition.depth is not None:

            end = start + condition.depth

        else:

            end = data_length

    start = max(0, min(start, data_length))
    end = max(0, min(end, data_length))

    return start, end


def _occurrences(
    condition: ContentCondition,
    data: bytes,
    previous_end: int | None,
) -> Iterator[tuple[int, int, int]]:
    """Yield ``(position, window_start, window_end)`` for every occurrence."""

    needle = condition.pattern

    if not needle:

        return

    window_start, window_end = _window(
        condition,
        len(data),
        previous_end,
    )

    if window_end - window_start < len(needle):

        return

    haystack = data.lower() if condition.nocase else data
    search = needle.lower() if condition.nocase else needle

    position = window_start

    while position <= window_end - len(needle):

        found = haystack.find(search, position, window_end)

        if found < 0:

            return

        yield found, window_start, window_end
        position = found + 1


def _match_buffer(
    conditions: tuple[ContentCondition, ...],
    data: bytes,
) -> list[tuple[int, int, int, int]] | None:
    """
    Return one full sequence of matches, or ``None``.

    Each tuple is ``(found, condition_index, window_start, window_end)``.
    Failed ``(index, previous_end)`` states are memoized so backtracking stays
    bounded on repetitive payloads.
    """

    failed: set[tuple[int, int | None]] = set()
    steps = 0
    max_steps = 1_000_000

    def search(
        index: int,
        previous_end: int | None,
    ) -> list[tuple[int, int, int, int]] | None:

        nonlocal steps

        if index >= len(conditions):

            return []

        state = (index, previous_end)

        if state in failed:

            return None

        condition = conditions[index]

        for found, window_start, window_end in _occurrences(
            condition,
            data,
            previous_end,
        ):

            steps += 1

            if steps > max_steps:  # pragma: no cover - defensive bound

                failed.add(state)
                return None

            rest = search(index + 1, found + len(condition.pattern))

            if rest is not None:

                return [
                    (found, index, window_start, window_end),
                    *rest,
                ]

        failed.add(state)

        return None

    return search(0, None)


def match_contents(
    conditions: tuple[ContentCondition, ...],
    buffers: list[Any],
) -> ContentMatchOutcome:
    """
    Match a rule's content sequence against the available buffers.

    A rule with no content conditions is a header-only rule and therefore
    matches trivially.
    """

    names = tuple(buffer.name for buffer in buffers)

    if not conditions:

        return ContentMatchOutcome(
            matched=True,
            reason="rule has no content condition",
            buffers_considered=names,
        )

    for buffer in buffers:

        sequence = _match_buffer(conditions, buffer.data)

        if sequence is None:

            continue

        matches: list[ContentMatch] = []

        for found, index, window_start, window_end in sequence:

            condition = conditions[index]

            matches.append(
                ContentMatch(
                    condition_index=index,
                    content=condition.pattern_text,
                    buffer=buffer.name,
                    position=found,
                    end=found + len(condition.pattern),
                    nocase=condition.nocase,
                    window_start=window_start,
                    window_end=window_end,
                )
            )

        return ContentMatchOutcome(
            matched=True,
            buffer=buffer.name,
            matches=tuple(matches),
            buffers_considered=names,
        )

    return ContentMatchOutcome(
        matched=False,
        reason=(
            "content sequence not found in "
            f"{len(buffers)} searched buffer(s)"
        ),
        buffers_considered=names,
    )


__all__ = [
    "ContentMatch",
    "ContentMatchOutcome",
    "match_contents",
]
