"""Reversible tokenization: persist what each surrogate stood for, so a
redaction can be undone.

By default piiguard forgets. The salt is ephemeral and no mapping is written,
so redaction is one-way and a leaked surrogate reveals nothing. A vault is the
opt-in exception: it records, on the local disk only, the surrogate -> original
mapping, so an authorized holder can later restore the source text.

The vault therefore contains the exact PII the redaction removed. It is as
sensitive as the original document -- treat it that way, and note that anyone
with the vault can re-identify the redacted output. Like everything else here
it never touches the network; it is a plain local file.
"""

from __future__ import annotations

import json
from pathlib import Path

VAULT_VERSION = 1


def load_vault(path: str) -> dict[str, dict[str, str]]:
    """Read a vault file into a surrogate -> entry map."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if data.get("version") != VAULT_VERSION:
        raise ValueError(
            f"unsupported vault version {data.get('version')!r}; "
            f"expected {VAULT_VERSION}"
        )
    return {e["surrogate"]: e for e in data.get("entries", [])}


def write_vault(
    path: str, entries: list[dict[str, str]], *, merge: bool = True
) -> int:
    """Write entries to a vault file, merging with any existing one by default.

    Merging lets several redactions share one vault: redact a directory of
    files, get a single key that restores all of them. Returns the total
    entry count written.
    """
    combined: dict[str, dict[str, str]] = {}
    p = Path(path)
    if merge and p.exists():
        combined = load_vault(path)
    for entry in entries:
        combined[entry["surrogate"]] = entry
    p.write_text(
        json.dumps(
            {"version": VAULT_VERSION, "entries": list(combined.values())},
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return len(combined)


def restore_text(text: str, vault: dict[str, dict[str, str]]) -> str:
    """Replace every surrogate found in text with its original value.

    Longer surrogates are substituted first so that one that is a prefix of
    another (``[SSN_1]`` vs ``[SSN_12]``) cannot corrupt the other. Surrogates
    not present in the text are simply ignored.
    """
    for surrogate in sorted(vault, key=len, reverse=True):
        text = text.replace(surrogate, vault[surrogate]["original"])
    return text
