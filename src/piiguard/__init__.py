"""PIIGuard - local-first PII detection and redaction.

Nothing in this package performs network I/O. See tests/test_no_egress.py.
"""

from .pipeline import Pipeline
from .types import Span

__version__ = "0.1.0"
__all__ = ["Pipeline", "Span"]
