#!/usr/bin/env python3
"""Emit machine-readable pyHanko verdicts for document timestamps.

Validates EVERY embedded document timestamp against one local trust
root and reports a per-timestamp verdict list plus aggregate flags.
Stdout is always exactly one JSON object; the exit code is 0 only when
at least one timestamp is present and all of them are intact and
trusted.
"""

import json
import sys
from datetime import datetime, timedelta, timezone
from importlib.metadata import version as package_version
from pathlib import Path
from typing import Any

from pyhanko.keys import load_cert_from_pemder
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_timestamp
from pyhanko_certvalidator import ValidationContext


def emit(summary: dict[str, Any]) -> None:
    print(json.dumps(summary, separators=(",", ":"), ensure_ascii=True))


def emit_versions() -> int:
    emit(
        {
            "tool": "verify-pades.py",
            "python": (
                f"{sys.version_info.major}.{sys.version_info.minor}."
                f"{sys.version_info.micro}"
            ),
            "pyhanko": package_version("pyhanko"),
            "certvalidator": package_version("pyhanko-certvalidator"),
        }
    )
    return 0


def parse_moment(raw: str) -> datetime:
    try:
        moment = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"invalid --moment {raw!r}: {error}") from error
    if moment.tzinfo is None:
        raise ValueError(f"--moment {raw!r} must carry a timezone")
    return moment.astimezone(timezone.utc)


def validate(
    pdf_path: Path, root_path: Path, moment: datetime | None, tolerance: float
) -> dict[str, Any]:
    with pdf_path.open("rb") as pdf_file:
        reader = PdfFileReader(pdf_file)
        timestamps = list(reader.embedded_timestamp_signatures)
        context = ValidationContext(
            trust_roots=[load_cert_from_pemder(root_path)],
            allow_fetching=False,
            moment=moment,
            time_tolerance=timedelta(seconds=tolerance),
        )
        per_timestamp = []
        for index, embedded in enumerate(timestamps):
            status = validate_pdf_timestamp(embedded, validation_context=context)
            per_timestamp.append(
                {
                    "index": index,
                    "intact": bool(status.intact),
                    "trusted": bool(status.trusted),
                }
            )
        summary: dict[str, Any] = {
            "timestampCount": len(per_timestamp),
            "intact": len(per_timestamp) > 0
            and all(item["intact"] for item in per_timestamp),
            "trusted": len(per_timestamp) > 0
            and all(item["trusted"] for item in per_timestamp),
            "timestamps": per_timestamp,
        }
        return summary


def main() -> int:
    args = sys.argv[1:]
    if args == ["--version"]:
        try:
            return emit_versions()
        except Exception as error:
            emit({"tool": "verify-pades.py", "error": f"{type(error).__name__}: {error}"})
            return 1

    moment: datetime | None = None
    tolerance = 1.0
    positional: list[str] = []
    index = 0
    try:
        while index < len(args):
            argument = args[index]
            if argument == "--moment":
                index += 1
                if index >= len(args):
                    raise ValueError("--moment requires a value")
                moment = parse_moment(args[index])
            elif argument == "--tolerance":
                index += 1
                if index >= len(args):
                    raise ValueError("--tolerance requires a value")
                tolerance = float(args[index])
                if not (tolerance >= 0):
                    raise ValueError("--tolerance must be non-negative")
            elif argument.startswith("-"):
                raise ValueError(f"unknown option: {argument}")
            else:
                positional.append(argument)
            index += 1
        if len(positional) != 2:
            raise ValueError("usage: verify-pades.py PDF ROOT_CERT [--moment ISO] [--tolerance SEC]")
        summary = validate(Path(positional[0]), Path(positional[1]), moment, tolerance)
    except Exception as error:
        emit(
            {
                "timestampCount": 0,
                "intact": False,
                "trusted": False,
                "timestamps": [],
                "error": f"{type(error).__name__}: {error}",
            }
        )
        return 2 if isinstance(error, ValueError) else 1

    emit(summary)
    ok = (
        summary["timestampCount"] >= 1 and summary["intact"] and summary["trusted"]
    )
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
