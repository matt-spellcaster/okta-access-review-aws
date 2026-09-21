"""Spreadsheet-safe CSV cells.

findings.csv and access_matrix.csv carry values that come from Okta profiles,
app labels, API token names and the HR roster, and reviewers open them in a
spreadsheet to record decisions. A value that starts with =, +, -, @, a tab or
a carriage return would run as a formula there, so such values are written
with a leading apostrophe. Every reader in this package strips it again, so
the tool always sees the original value.
"""

from __future__ import annotations

import csv
import io

FORMULA_STARTS = ("=", "+", "-", "@", "\t", "\r")
QUOTE = "'"


def cell(value):
    """What to write for one value. A string a spreadsheet could execute gets an
    apostrophe in front; so does a string that already starts with one, so that
    reading back is unambiguous."""
    if isinstance(value, str) and value.startswith(FORMULA_STARTS + (QUOTE,)):
        return QUOTE + value
    return value


def value(text: str) -> str:
    """The original value of a cell written by cell()."""
    return text[1:] if text.startswith(QUOTE) else text


def read_rows(text: str) -> list[dict]:
    """Rows of a CSV written by report._write_csv, with every cell unescaped."""
    return [{k: value(v) if isinstance(v, str) else v for k, v in row.items()}
            for row in csv.DictReader(io.StringIO(text))]
