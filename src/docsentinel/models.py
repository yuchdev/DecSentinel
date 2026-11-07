"""Stable data contracts shared by the CLI and library."""

from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class Document:
    """Discovered documentation document metadata."""

    path: str
    bytes: int


@dataclass(frozen=True)
class Finding:
    """A single rule violation finding.

    The identity of a finding is ``rule``, ``path``, ``message``, ``severity`` and
    ``line``. The optional enrichment fields ``column``, ``value`` and ``type``
    (Milestone 0007) are report-only attributes: they are excluded from equality and
    hashing (``compare=False``) and from baseline fingerprints, so a detector that
    starts populating them never changes ``Finding``/``ScanResult`` equality or a
    recorded baseline.

    :ivar rule: The producing rule code, for example ``DS101``.
    :ivar path: The document path relative to the scan root.
    :ivar message: The full detector message.
    :ivar severity: ``error`` or ``warning``.
    :ivar line: 1-based source line, or ``None`` when not located.
    :ivar column: 1-based column (in code points) of the offending token on
        ``line``, or ``None`` when the detector does not extract it.
    :ivar value: The offending token the detector already echoes in ``message``
        (a link target, a path), never a surrounding snippet; ``None`` when not
        extracted. Untrusted: it originates in scanned content.
    :ivar type: Short finding category such as ``dangling link``; ``None`` when the
        detector gives none (the report model then derives it from the rule title).
    """

    rule: str
    path: str
    message: str
    severity: str = "warning"
    line: Optional[int] = None
    column: Optional[int] = field(default=None, compare=False)
    value: Optional[str] = field(default=None, compare=False)
    type: Optional[str] = field(default=None, compare=False)


@dataclass(frozen=True, kw_only=True)
class ScanResult:
    """The result of a documentation scan.

    :ivar rules_evaluated: Number of active rules that genuinely evaluated (an
        active opt-in rule whose policy is off is not counted). ``0`` when no rule
        ran. ``notice`` is built from this value.
    :ivar opt_in_off: ``(code, option)`` pairs, in rule-code order, for active
        opt-in policy rules whose enabling option is not set. ``notice`` is built
        from this value.
    """

    schema_version: int = 1
    profile: str
    documents: tuple[Document, ...]
    findings: tuple[Finding, ...]
    enabled_rules: tuple[str, ...]
    pending: tuple[str, ...]
    notice: str = "Detection rules are not implemented in M0; this is an inventory only."
    rules_evaluated: int = 0
    opt_in_off: tuple[tuple[str, str], ...] = ()
