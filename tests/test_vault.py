"""Reversible tokenization: redact -> vault -> restore must round-trip, and the
vault must exist only when reversal is actually possible.
"""

from __future__ import annotations

import pytest

from piiguard.pipeline import Pipeline
from piiguard.policy import Policy
from piiguard.vault import VAULT_VERSION, load_vault, restore_text, write_vault


def _vault_from(engine) -> dict[str, dict[str, str]]:
    return {e["surrogate"]: e for e in engine.vault_entries()}


@pytest.mark.parametrize("mode", ["pseudonymize", "label"])
def test_redact_then_restore_round_trips(mode):
    text = "Email a@b.example, again a@b.example; SSN 078-05-1120 on file."
    pipe = Pipeline(policy=Policy(default=mode))
    result = pipe.redact(text)
    assert result.redacted != text  # something was actually redacted
    restored = restore_text(result.redacted, _vault_from(pipe.engine))
    assert restored == text


def test_repeated_value_makes_one_entry_and_restores_everywhere():
    text = "a@b.example ... a@b.example ... a@b.example"
    pipe = Pipeline(policy=Policy(default="pseudonymize"))
    result = pipe.redact(text)
    entries = pipe.engine.vault_entries()
    assert len(entries) == 1  # coreference collapses to a single mapping
    assert restore_text(result.redacted, _vault_from(pipe.engine)) == text


def test_restore_preserves_original_casing():
    # Same value, different case: the dedup key is lowercased, but the vault
    # keeps the first surface form so restore is exact.
    text = "Write to Sam@X.Example."
    pipe = Pipeline(policy=Policy(default="label"))
    result = pipe.redact(text)
    entry = pipe.engine.vault_entries()[0]
    assert entry["original"] == "Sam@X.Example"
    assert restore_text(result.redacted, _vault_from(pipe.engine)) == text


def test_mask_mode_has_no_vault_entries():
    pipe = Pipeline(policy=Policy(default="mask"))
    pipe.redact("SSN 078-05-1120 here.")
    assert pipe.engine.vault_entries() == []


def test_restore_is_substring_safe():
    # [SSN_1] is a prefix of [SSN_12]; longer surrogates must resolve first.
    vault = {
        "[SSN_1]": {"surrogate": "[SSN_1]", "original": "111-11-1111"},
        "[SSN_12]": {"surrogate": "[SSN_12]", "original": "222-22-2222"},
    }
    out = restore_text("first [SSN_12] then [SSN_1]", vault)
    assert out == "first 222-22-2222 then 111-11-1111"


def test_write_and_load_vault_merges(tmp_path):
    path = str(tmp_path / "key.json")
    write_vault(path, [{"label": "EMAIL", "surrogate": "s1", "original": "a@b.example"}])
    write_vault(path, [{"label": "SSN", "surrogate": "s2", "original": "078-05-1120"}])
    loaded = load_vault(path)
    assert set(loaded) == {"s1", "s2"}  # second write merged, did not overwrite


def test_load_rejects_unknown_version(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text(f'{{"version": {VAULT_VERSION + 1}, "entries": []}}')
    with pytest.raises(ValueError):
        load_vault(str(path))
