"""Minimal JSON Lines reader / writer.

Writes one JSON object per line, ``ensure_ascii=False`` so Vietnamese text
stays readable. Reading is tolerant: a malformed line is skipped instead of
terminating the whole file.
"""

import json
from pathlib import Path
from typing import Any, Iterator


class JsonlWriter:
    """Append-only JSON Lines writer that creates parent folders."""

    def __init__(self, path: str | Path) -> None:

        self.path = Path(path)

        self.path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        self._handle = self.path.open(
            "a",
            encoding="utf-8",
        )

    def write(self, record: dict[str, Any]) -> None:

        json.dump(
            record,
            self._handle,
            ensure_ascii=False,
            separators=(",", ":"),
        )

        self._handle.write("\n")

    def flush(self) -> None:

        self._handle.flush()

    def close(self) -> None:

        if not self._handle.closed:

            self._handle.flush()
            self._handle.close()

    def __enter__(self) -> "JsonlWriter":

        return self

    def __exit__(self, *exc_info) -> None:

        self.close()


def read_jsonl(path: str | Path) -> Iterator[dict[str, Any]]:
    """Yield parsed JSON objects; skip blank or malformed lines."""

    with Path(path).open(
        "r",
        encoding="utf-8",
    ) as handle:

        for line in handle:

            line = line.strip()

            if not line:
                continue

            try:

                parsed = json.loads(line)

            except json.JSONDecodeError:

                continue

            if isinstance(parsed, dict):

                yield parsed


def reset_file(path: str | Path) -> None:
    """Remove an output file so results are never accidentally appended."""

    output = Path(path)

    if output.exists():

        output.unlink()


__all__ = [
    "JsonlWriter",
    "read_jsonl",
    "reset_file",
]
