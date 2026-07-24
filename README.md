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
| 2. NER (spaCy) | ✅ built, opt-in `--ner` | names, orgs, locations |
| 3. local LLM (Ollama) | planned | context-dependent PII the first two miss |

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

> Baseline as of the seed corpus (10 documents, 65 spans), layer 1 only:
> **P 0.833 / R 0.692 / F1 0.756**. Recall is dragged down by PERSON, ORG,
> ADDRESS and DOB, which layer 1 cannot see at all -- that is the gap layer 2
> exists to close. Target 30-50 documents before treating these as stable.

## Not yet handled

- Images and PDFs (OCR path)
- Structured formats — CSV/JSON column-aware redaction
- Non-US phone, national ID, and address formats
- Reversible tokenization with a persisted local vault

## License

Apache-2.0
