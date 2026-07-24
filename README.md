# PIIGuard

Local-first PII detection and redaction.

The premise: a PII scrubber that uploads your data has an unresolvable trust
problem — to use it, you must do the exact thing you were trying to avoid.
So this one never leaves your machine, and CI proves it.

```
detect  →  merge  →  policy  →  transform  →  verify  →  output
```

## No-egress guarantee

`tests/test_no_egress.py` patches out `socket`, DNS resolution, and
`http.client`, then runs a full scan/redact/verify cycle. Any attempt to touch
the network raises. CI runs it first, before anything else.

This turns "trust us, it's local" into a property under test. If someone later
adds a telemetry ping or a model download at runtime, the build breaks and they
have to defend it in review.

The one exception is layer 3, which talks to a model server on this same
machine. The guarantee is refined, not dropped: "never leaves your machine"
becomes "never leaves loopback." All layer-3 traffic goes through a single
guard (`localnet.py`) that permits `127.0.0.0/8` and `::1` and raises on
anything else — including a DNS name it would have to resolve — and the test
suite asserts both halves: loopback allowed, external refused.

## Install

```bash
git clone <your-repo> && cd piiguard
pip install -e ".[dev]"
pytest
```

Zero runtime dependencies for the base tool — stdlib only.

## Use

```bash
piiguard scan notes.txt
piiguard scan notes.txt --json

piiguard redact notes.txt -o clean.txt
piiguard redact notes.txt --policy pseudonymize
piiguard redact notes.txt --set SSN=mask --set IPV4=keep
cat log.txt | piiguard redact - --policy mask

piiguard scan notes.txt --ner        # add the NER layer (names, orgs, addresses)
piiguard redact notes.txt --ner
piiguard redact notes.txt --ner --llm  # add the local Ollama layer too
```

The base tool runs layer 1 only, with zero installs. `--ner` opts into the
spaCy layer; it is off by default so the tool stays stdlib-only until you ask
for more coverage. Without the model installed, `--ner` prints how to get it
rather than failing obscurely.

### Policy modes

| mode | `078-05-1120` becomes | use when |
|---|---|---|
| `mask` | `***-**-****` | shape matters, value doesn't |
| `label` | `[SSN_1]` | default; readable and unambiguous |
| `pseudonymize` | stable fake value | the document must stay natural to read |
| `keep` | unchanged | allowlisted labels |

Pseudonymization is deterministic within a run: the same input value always maps
to the same surrogate, so `Alice` stays one consistent person across a document
and coreference survives redaction. The salt is ephemeral by default, so
surrogates are **not** reversible unless you deliberately persist it.

## Detector layers

| layer | status | what it catches |
|---|---|---|
| 1. regex + validators | ✅ built | SSN, credit card, phone, email, IPv4, IBAN |
| 1b. table structure | ✅ built | whole-cell PII in CSV/TSV name/org/address columns |
| 2. NER (spaCy) | ✅ built, opt-in `--ner` | names, orgs, locations |
| 3. local LLM (Ollama) | ✅ built, opt-in `--llm` | context-dependent PII the first two miss |

Layer 3 needs a local Ollama server (`ollama serve`, then `ollama pull
llama3.2`); without one, `--llm` prints that it was skipped and the pipeline
proceeds on layers 1–2 rather than failing. The model returns verbatim
substrings, never offsets — piiguard locates them itself and discards anything
the model did not copy exactly, so a hallucinated span cannot corrupt output.
Its quality is not yet on the scorecard below (no Ollama in CI); the offset
mapping, loopback guard, and fail-closed behavior are covered by tests.

The structure layer is also stdlib-only. In a delimited table it reads the
header and redacts entire cells of the person/org/address columns — catching
names a per-cell model fumbles (`Nia Achterberg` splits or vanishes) while
leaving validator-backed columns (email, phone, IP) to layer 1, so a row's
placeholder hard negatives still get correctly rejected.

Layer 1 first on purpose: no dependencies, microsecond latency, and real
validators (Luhn, SSA allocation rules, IBAN mod-97) rather than shape-matching
alone. That kills most look-alike false positives before any model is involved.
Layers 2 and 3 have to beat this baseline on the scorecard to earn their place.

## Evaluation

```bash
python eval/score.py            # precision / recall / F1 per label
python eval/score.py --partial  # count overlap as a hit
```

Authoring fixtures — never hand-count offsets:

```bash
# in eval/raw/mydoc.txt:  Call {{PHONE_US:415-555-0142}} or 4111 dollars.
python eval/make_fixture.py eval/raw/mydoc.txt --id mydoc
```

Every fixture should include **hard negatives**: values that look like PII and
aren't. The seed corpus has an invalid-area SSN, a bare number that resembles a
card, and an out-of-range IP. Those are what stop the detector getting lazy.

> Seed corpus, 10 documents. The number that matters is the **character-level
> leak rate** — the fraction of labeled PII characters surviving redaction:
>
> | | leak rate | over-redaction | span F1 |
> |---|---|---|---|
> | layer 1 (regex + structure) | 26.2% | 5.0% | 0.837 |
> | layer 1 + `--ner` | **1.7%** | 5.6% | 0.965 |
>
> Span F1 is a diagnostic only: it scores a one-character-short span the same
> as a total miss and penalizes over- and under-redaction equally, which is
> wrong for a scrubber. The residual leak is now a single missed organization
> name — the gap layer 3 exists to close. Target 30-50 documents before
> treating these as stable.

## Not yet handled

- Images and PDFs (OCR path)
- JSON / nested structured formats (CSV and TSV columns are handled)
- Non-US phone, national ID, and address formats
- Reversible tokenization with a persisted local vault

## License

Apache-2.0
