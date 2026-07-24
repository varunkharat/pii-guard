"""Structure-aware detection for delimited tables (CSV/TSV).

Free-text NER segments names badly inside a CSV row: "Marisol Ferrante" in a
cell arrives as just "Ferrante", "Corinne Ashby" is mislabeled an ORG, and
"Nia Achterberg" is missed outright. Per-cell detection cannot be trusted for
the very columns that matter most.

The structure carries information the model ignores: a column headed `name`
holds people, whichever way the model parses each cell. So when the text is a
consistent table, this detector reads the header and redacts entire cells of
the person / organization / address columns.

Deliberately narrow, for two reasons:

  * Only the NER-shaped labels (PERSON, ORG, ADDRESS) get whole-cell
    treatment. Columns like email, phone and IP already have validated regex
    detectors that correctly reject a row's placeholder values
    (noreply@example.invalid, 0000000000). Redacting those columns wholesale
    would undo that and re-flag the hard negatives.
  * A whole-cell rule redacts a synthetic "Test Account" sitting in a name
    column. That is the right trade for a scrubber: over-redacting one placeholder
    costs a token; leaking a real person's given name costs everything, and
    catching it per-cell is exactly what fails here.

stdlib only -- this runs in the base tool with no model and no network.
"""

from __future__ import annotations

from ..types import Span

# Header token -> label. Matched against alphanumeric tokens of the header
# cell (so "last_name" -> {last, name} hits PERSON, but "filename" does not).
# Only labels without a reliable value-level validator are handled here.
COLUMN_LABELS: list[tuple[str, frozenset[str]]] = [
    ("PERSON", frozenset({
        "name", "names", "fullname", "firstname", "lastname",
        "customer", "employee", "patient", "contact", "applicant", "person",
    })),
    ("ORG", frozenset({
        "company", "organization", "organisation", "org",
        "employer", "vendor", "business",
    })),
    ("ADDRESS", frozenset({
        "address", "street", "city", "zip", "zipcode", "postal", "state",
    })),
]

# Column position is as strong a signal as a validated regex: a cell under a
# `name` header holds a person however the free-text model parses it. So these
# score 1.0, and on any overlap the merge's length tie-break keeps the fuller
# span -- a whole-cell address wins over the regex state+ZIP sitting inside it.
STRUCT_SCORE = 1.0

MIN_TABLE_ROWS = 3          # header + at least two data rows
MIN_TABLE_COLUMNS = 2
TABLE_ROW_FRACTION = 0.6    # of non-empty lines that must share the modal width
DELIMITERS = (",", "\t")


def _tokens(header_cell: str) -> set[str]:
    out: list[str] = []
    word: list[str] = []
    for ch in header_cell.lower():
        if ch.isalnum():
            word.append(ch)
        elif word:
            out.append("".join(word))
            word = []
    if word:
        out.append("".join(word))
    return set(out)


def _classify(header_cell: str) -> str | None:
    toks = _tokens(header_cell)
    for label, keywords in COLUMN_LABELS:
        if toks & keywords:
            return label
    return None


def _split_fields(line: str, delim: str) -> list[tuple[int, int]]:
    """Return (start, end) of each field, trimmed, with minimal quote handling.

    Offsets are relative to the line. Quoted fields have their surrounding
    quotes stripped; a doubled quote inside is treated as content.
    """
    fields: list[tuple[int, int]] = []
    i, n = 0, len(line)
    while True:
        if i < n and line[i] == '"':
            i += 1
            content_start = i
            while i < n:
                if line[i] == '"':
                    if i + 1 < n and line[i + 1] == '"':
                        i += 2
                        continue
                    break
                i += 1
            content_end = i
            if i < n and line[i] == '"':
                i += 1
            while i < n and line[i] != delim:
                i += 1
            fields.append(_trim(line, content_start, content_end))
        else:
            start = i
            while i < n and line[i] != delim:
                i += 1
            fields.append(_trim(line, start, i))
        if i < n and line[i] == delim:
            i += 1
        else:
            break
    return fields


def _trim(line: str, start: int, end: int) -> tuple[int, int]:
    while start < end and line[start].isspace():
        start += 1
    while end > start and line[end - 1].isspace():
        end -= 1
    return start, end


class StructuredDetector:
    """Whole-cell redaction of person/org/address columns in a table."""

    name = "structured"

    def detect(self, text: str) -> list[Span]:
        for delim in DELIMITERS:
            spans = self._detect_with(text, delim)
            if spans:
                return spans
        return []

    def _detect_with(self, text: str, delim: str) -> list[Span]:
        # Line offsets, preserving positions for span coordinates.
        lines: list[tuple[str, int]] = []
        offset = 0
        for line in text.split("\n"):
            lines.append((line, offset))
            offset += len(line) + 1

        widths: dict[int, int] = {}
        nonempty = 0
        for line, _ in lines:
            if not line.strip():
                continue
            nonempty += 1
            w = len(_split_fields(line, delim))
            widths[w] = widths.get(w, 0) + 1
        if not widths:
            return []

        modal = max(widths, key=lambda w: widths[w])
        if modal < MIN_TABLE_COLUMNS:
            return []
        if widths[modal] < MIN_TABLE_ROWS:
            return []
        if widths[modal] < TABLE_ROW_FRACTION * nonempty:
            return []

        # The header is the first line of modal width; classify its columns.
        header = None
        for line, base in lines:
            if line.strip() and len(_split_fields(line, delim)) == modal:
                header = (line, base)
                break
        if header is None:
            return []

        header_line, _ = header
        col_labels: dict[int, str] = {}
        for idx, (s, e) in enumerate(_split_fields(header_line, delim)):
            label = _classify(header_line[s:e])
            if label is not None:
                col_labels[idx] = label
        if not col_labels:
            return []

        spans: list[Span] = []
        seen_header = False
        for line, base in lines:
            if not line.strip():
                continue
            fields = _split_fields(line, delim)
            if len(fields) != modal:
                continue
            if not seen_header:
                seen_header = True  # skip the header row itself
                continue
            for idx, label in col_labels.items():
                s, e = fields[idx]
                if s >= e:  # empty cell
                    continue
                spans.append(
                    Span(
                        start=base + s,
                        end=base + e,
                        label=label,
                        text=line[s:e],
                        score=STRUCT_SCORE,
                        detector=self.name,
                    )
                )
        return spans
