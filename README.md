# PIIGuard

Local-first PII detection and redaction.

The premise: a PII scrubber that uploads your data has an unresolvable trust
problem — to use it, you must do the exact thing you were trying to avoid.
So this one never leaves your machine, and CI proves it.

```
detect  →  merge  →  policy  →  transform  →  verify  →  output
```

## Results

Measured on a 33-document labeled corpus (`tests/fixtures/`), layers 1–2:

| metric | value |
|---|---|
| **PII characters leaked** | **0.2%** |
| clean text over-redacted | 7.1% |
| span-level F1 | 0.931 |

Leak rate is the headline number and the one to argue about. Span F1 is a
diagnostic: it scores a span that is one character short the same as one that
missed entirely, and it penalizes over-redaction and under-redaction equally.
For a scrubber those are not equally bad. What matters is which characters
survive into the output — so that is what gets measured.

Per-label span scores:

| label | P | R | layer |
|---|---|---|---|
| SSN, CREDIT_CARD, IBAN, PHONE_US, DOB, IPV4 | 1.000 | 1.000 | regex |
| SECRET | 1.000 | 1.000 | regex + structure |
| EMAIL | 0.977 | 1.000 | regex |
| ADDRESS | 0.929 | 1.000 | regex + NER + structure + join |
| PERSON | 0.750 | 1.000 | NER + structure |
| ORG | 0.658 | 0.893 | suffix + NER + structure |

The leaked characters are one organization name: "Brightwave", a coined
one-word name with no legal or sector suffix, in a terse bullet list that
gives spaCy no context. That fixture was added deliberately — the corpus
previously contained no unsuffixed org, so the then-0.0% leak rate was
measured against a corpus that never tested the known hard case. 0.2% against
a corpus that does is the honest number, and closing it is layer 3's job.

The rest of the error is over-redaction — mostly spaCy tagging document
titles ("Form W-2 Wage and Tax Statement") as organizations, which is the
cheap direction to be wrong in and is left alone deliberately. Chasing that
precision means suppressing ORG spans, and ORG recall is what the leak rate
is made of.

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

# Reversible: write a local key, then undo the redaction later
piiguard redact notes.txt --policy pseudonymize --vault notes.key.json -o clean.txt
piiguard restore clean.txt --vault notes.key.json -o notes.restored.txt

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
and coreference survives redaction. The salt is ephemeral by default, so by
default a redaction is one-way.

To make it reversible, pass `--vault PATH`. That writes a local key file mapping
each surrogate back to its original, and `piiguard restore` uses it to undo the
redaction (works for `label` and `pseudonymize`; `mask` is lossy). The vault
holds the exact PII that was removed — it is as sensitive as the source, and,
like everything here, it never leaves your machine.

## Detector layers

| layer | status | what it catches |
|---|---|---|
| 1. regex + validators | ✅ built | SSN, credit card, phone, email, IPv4, IBAN, API keys / URL credentials |
| 1b. structure | ✅ built | whole-value PII in CSV/TSV columns and JSON keys |
| 1c. org suffixes | ✅ built | organizations by legal or sector tail |
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
header and redacts entire cells of the person/org/address/secret columns; in
JSON it does the same for values whose key names one of those
(`"customer_name": "..."`, `"api_key": "..."`). Either way it catches what a
per-value pass cannot: names a model fumbles (`Nia Achterberg` splits or
vanishes) and secrets with no recognizable prefix — an `api_key` can be any
string, so the key is the only reliable signal. Validator-backed fields
(email, phone, IP) are left to layer 1, so a record's placeholder hard
negatives still get correctly rejected.

**Layer 1 first on purpose:** no dependencies, microsecond latency, and real
validators (Luhn, SSA allocation rules, IBAN mod-97) rather than shape-matching
alone. That kills most look-alike false positives before any model is involved.
Layers 2 and 3 have to beat this baseline on the scorecard to earn their place.

**Secrets.** API keys and credentials ride the same layer on two signals.
Vendor prefixes are unmistakable by design — that is what the prefix is for —
so `sk_live_…`, `ghp_…`, `AKIA…`, `xoxb-…`, and JWT-shaped `eyJ…` tokens need
no context. A password inside a connection URL is marked by its position:
`postgres://svc_app:hunter2@db` redacts exactly the password slot, never the
username or host. Placeholders are rejected as hard negatives — `${DB_PASSWORD}`
names a secret, `********` used to be one; neither is one now.

**Layer 1c — organization suffixes.** spaCy has never seen "Copperline Mutual"
or "Valley Health Partners", and unlike a person's name there is no morphology
to guess from — so it returns nothing and the name survives. But English names
organizations with a closed set of tails: a legal form (Inc, LLC, Holdings) or
the sector itself (Insurance, Analytics, University). A capitalized run ending
in one of those is an organization whether or not a model has heard of it, and
that is a lexical fact needing no model to exploit. On the corpus the
model-free tool's ORG precision is 1.000 — every suffix match is a real
organization — and its recall is 0.857, the misses being exactly the coined
suffix-less names ("Brightwave", "Copperfox") the lexicon cannot reach. It
also *reduced*
over-redaction: scoring a suffix match as high as a validated regex means it
wins the merge against spaCy's looser boundary, so "Harborlight Insurance -
Auto" becomes "Harborlight Insurance".

**Layer 2 — spaCy NER.** People, organizations, places. Presidio was tried
first and removed: its regex recognizers lose to layer 1 on every shared label,
and it drops `ORGANIZATION` from its default entity set, so it was a wrapper
around spaCy that made spaCy worse.

**Join pass.** NER returns addresses in fragments — a street, a city, a ZIP,
never one span. Redacting the pieces leaves the connective tissue behind, and a
suite number plus a ZIP is still identifying. `join_adjacent` fuses fragments
separated only by connective text, never across a line boundary, and pulls in a
leading street number. The rule is biased toward over-redaction on purpose.

**Layer 3 — local LLM (Ollama).** For context-dependent PII the first layers
miss (an oddly phrased organization, an obliquely named person), an optional
pass asks a model running on this machine. It returns verbatim substrings,
never offsets — piiguard locates them itself and discards anything the model
did not copy exactly, so a hallucinated span cannot corrupt output. A missing
or slow server is a no-op, never an error. Its quality is not yet on the
scorecard (no Ollama in CI); the offset mapping, loopback guard, and
fail-closed behavior are covered by tests.

## Evaluation

```bash
python eval/score.py            # precision / recall / F1 per label
python eval/score.py --partial  # count overlap as a hit
python eval/score.py --llm      # include layer 3 (needs a local Ollama server)

# Gates (exit 2 on breach) — CI enforces the first one:
python eval/score.py --no-ner --fail-on-leak SSN,CREDIT_CARD,IBAN,EMAIL,PHONE_US,IPV4,DOB,SECRET
python eval/score.py --max-leak-rate 5
```

The validator-backed labels are pure layer 1, so their leak rate is gated in
CI: if an SSN, card, IBAN, email, phone, IP, DOB, or secret ever survives
redaction, the build fails. Like the no-egress test, this makes a core promise
a property under test rather than a claim.

Authoring fixtures — never hand-count offsets:

```bash
# in eval/raw/mydoc.txt:  Call {{PHONE_US:415-555-0142}} or 4111 dollars.
python eval/make_fixture.py eval/raw/mydoc.txt --id mydoc
```

Every fixture should include **hard negatives**: values that look like PII and
aren't. The seed corpus has an invalid-area SSN, a bare number that resembles a
card, and an out-of-range IP. Those are what stop the detector getting lazy.

> Corpus, 33 documents. The number that matters is the **character-level
> leak rate** — the fraction of labeled PII characters surviving redaction:
>
> | | leak rate | over-redaction | span F1 |
> |---|---|---|---|
> | layer 1 (regex + structure + suffix) | 23.8% | 2.0% | 0.823 |
> | layer 1 + `--ner` | **0.2%** | 7.1% | 0.931 |
>
> Span F1 is a diagnostic only: it scores a one-character-short span the same
> as a total miss and penalizes over- and under-redaction equally, which is
> wrong for a scrubber. The residual layer-1 leak is almost entirely person
> names and address fragments, which is what the NER layer exists to close.
> The over-redaction is mostly spaCy over-tagging document titles, which is
> cheap by design. At 33 documents this is the low end of a stable range.

## Not yet handled

- **Organization names without a suffix.** A one-word or coined name with no
  legal or sector tail ("Brightwave" alone, "Northwind") is reachable by
  neither layer 1c's lexicon nor spaCy's training — unless prose context
  rescues it ("the team at Northwind" is caught; a terse "Brightwave renewal:"
  bullet is not). The corpus now contains both cases, and the miss is the
  entirety of the 0.2% leak. This is what layer 3 exists to close, pending
  validation against a real model.
- **Layer 3 quality is unmeasured.** The plumbing is tested (loopback guard,
  offset mapping, fail-closed), but `eval/score.py --llm` has never been run
  against a live model, so "layer 3 closes the org gap" is a design intent,
  not a result.
- **ORG precision (0.658).** spaCy tags document titles as organizations. Left
  alone on purpose: the fix is suppression, and suppression trades against the
  recall the leak rate is made of.
- **Unprefixed secrets in prose.** The SECRET layer needs a vendor prefix, a
  URL password slot, or a secret-named key/column. A bare hex blob in a
  sentence ("the key is a3f9...") and PEM private-key blocks are not caught;
  a generic entropy detector is the known fix and brings a real
  false-positive cost (git SHAs, request IDs).
- Images and PDFs (OCR path).
- Deeply nested / array-of-object JSON (flat JSON objects, CSV, and TSV are
  handled).
- Non-US phone, national ID, and address formats.

## License

Apache-2.0 — see [LICENSE](LICENSE).
