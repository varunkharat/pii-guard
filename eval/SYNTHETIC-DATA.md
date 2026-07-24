# Synthetic data notice

Every value in `eval/raw/` and `tests/fixtures/` is invented. No real person,
household, account, or credential appears anywhere in this corpus.

Specifically:

- **Names** are constructed given/surname pairs. They are deliberately
  *plausible* rather than nonsensical, because the NER layer is trained on
  real-world name shapes — a corpus of `Xzzq Vbbn` would score well and tell
  you nothing about behaviour on real documents. Any resemblance to a
  particular person is coincidental and unintended.
- **Street addresses** use invented street names. City, state, and ZIP are
  real, because those are not personal data and the model needs genuine
  place names to detect locations at all.
- **Phone numbers** are in the 555-01XX range reserved for fiction (NANP).
- **Email domains** end in `.example`, reserved by RFC 2606 and permanently
  unregistrable.
- **Card numbers** are the standard test values published by card networks.
- **The SSNs** are drawn from ranges the SSA has never issued.
- **IBANs** are the checksum-valid examples from the ISO 13616 documentation.
- **Organizations** are invented. Any real-world vendor, employer, or school
  names have been replaced.

## If you add fixtures

Do not paste real data, even redacted, even your own. Use `.example` domains,
555-01XX numbers, and invented streets and employers. Add hard negatives —
values that look like PII and aren't — because those are what stop the
detector getting lazy.

`.gitignore` excludes `eval/real/` for anyone who wants to evaluate against
genuine documents locally. Nothing in that directory is ever committed.
