"""Helpers that keep the pipeline working on plain dictionaries.

Downstream modules must not depend on Scapy, but they should still accept a
``NormalizedEvent`` for convenience. ``as_event_dict`` normalizes either input
into a JSON-compatible dictionary.
"""

from typing import Any


def as_event_dict(event: Any) -> dict[str, Any]:
    """
    Return a JSON-serializable dictionary for ``event``.

    Accepts either a mapping or any object exposing ``to_dict()`` (such as
    ``NormalizedEvent``). Adding a ``bytes`` value anywhere is avoided here.
    """

    if isinstance(event, dict):

        return dict(event)

    to_dict = getattr(event, "to_dict", None)

    if callable(to_dict):

        result = to_dict()

        if isinstance(result, dict):

            return result

    raise TypeError(
        "Event must be a dict or expose to_dict(), got "
        f"{type(event).__name__}"
    )
