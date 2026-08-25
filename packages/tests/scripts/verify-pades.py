#!/usr/bin/env python3
"""Emit a machine-readable pyHanko verdict for one local document timestamp."""

import json
import sys
from pathlib import Path
from typing import Any

from pyhanko.keys import load_cert_from_pemder
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_timestamp
from pyhanko_certvalidator import ValidationContext


def emit(summary: dict[str, Any]) -> None:
    print(json.dumps(summary, separators=(",", ":"), ensure_ascii=True))


def validate(pdf_path: Path, root_path: Path) -> dict[str, Any]:
    with pdf_path.open("rb") as pdf_file:
        reader = PdfFileReader(pdf_file)
        timestamps = list(reader.embedded_timestamp_signatures)
        summary: dict[str, Any] = {
            "timestampCount": len(timestamps),
            "intact": False,
            "trusted": False,
        }
        if len(timestamps) != 1:
            return summary

        context = ValidationContext(
            trust_roots=[load_cert_from_pemder(root_path)], allow_fetching=False
        )
        status = validate_pdf_timestamp(timestamps[0], validation_context=context)
        summary["intact"] = bool(status.intact)
        summary["trusted"] = bool(status.trusted)
        return summary


def main() -> int:
    if len(sys.argv) != 3:
        emit(
            {
                "timestampCount": 0,
                "intact": False,
                "trusted": False,
                "error": "usage: verify-pades.py PDF ROOT_CERT",
            }
        )
        return 2

    try:
        summary = validate(Path(sys.argv[1]), Path(sys.argv[2]))
    except Exception as error:
        emit(
            {
                "timestampCount": 0,
                "intact": False,
                "trusted": False,
                "error": f"{type(error).__name__}: {error}",
            }
        )
        return 1

    emit(summary)
    return 0 if summary["timestampCount"] == 1 and summary["intact"] and summary["trusted"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
