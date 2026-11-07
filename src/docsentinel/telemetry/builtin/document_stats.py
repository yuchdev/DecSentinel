"""``builtin:document_stats``: a custom per-document calculation (Story 04.0 Task 02).

The shipped "write your own" example: it computes a value instead of looking one up.

* Per document (``doc.ext.document_stats``): ``problem_count_per_kb``, the number of
  problems per KiB of the document, ``round(problems / (bytes / 1024), 3)``.
* Per run (``ext.document_stats``): ``worst_documents``, at most
  :data:`WORST_DOCUMENTS` documents with problems ordered by ``(-density, path)``.

Threat model 0007-extensions mitigations implemented here:

* **M34** -- ``bytes is None`` (a finding path outside the discovered inventory,
  such as a DS204 Python source) gives ``null`` and keeps the document out of
  ``worst_documents``; ``bytes == 0`` gives ``0.0``. The value is a ratio of
  non-negative integers with a positive divisor, so it is never NaN, infinite or
  ``-0.0``. Ties are broken by path, so the output is identical on every run.
* **M18** -- the run hook selects the worst documents once, with a heap of size
  :data:`WORST_DOCUMENTS` (``heapq.nsmallest``), and the document hook is O(1), so
  the extension costs O(D + F) per render.
"""

import heapq
from collections.abc import Iterator, Mapping
from typing import Final, Optional

from docsentinel.config import Config

#: The extension name.
EXTENSION_NAME: Final[str] = "document_stats"

#: Most entries in ``worst_documents``.
WORST_DOCUMENTS: Final[int] = 5

#: Digits kept by ``problem_count_per_kb``.
DENSITY_DIGITS: Final[int] = 3


def problem_count_per_kb(problems: object, size: object) -> Optional[float]:
    """Return the problem density of one document (M34).

    :param problems: The document's ``problem_count``.
    :param size: The document's ``bytes``; ``None`` outside the inventory.
    :returns: ``None`` when either value is not an exact non-negative ``int`` (so
        ``bytes: null``), ``0.0`` for an empty document, else
        ``round(problems / (bytes / 1024), 3)``.
    """
    if type(problems) is not int or type(size) is not int or problems < 0 or size < 0:
        return None
    if size == 0:
        return 0.0
    return round(problems / (size / 1024), DENSITY_DIGITS)


def _ranked(documents: object) -> Iterator[tuple[float, str, dict]]:
    """Yield ``(-density, path, entry)`` for every document that can be ranked.

    A document is ranked when it has at least one problem and a measurable size;
    clean documents and documents outside the inventory (``bytes: null``) are skipped.

    :param documents: The frozen ``documents`` list of the run context.
    :yields: The sort key parts and the ``worst_documents`` entry.
    """
    for doc in documents if isinstance(documents, tuple) else ():
        density = problem_count_per_kb(doc["problem_count"], doc["bytes"])
        if density is None or doc["problem_count"] == 0:
            continue
        entry = {
            "path": doc["path"],
            "bytes": doc["bytes"],
            "problem_count": doc["problem_count"],
            "problem_count_per_kb": density,
        }
        yield -density, doc["path"], entry


class DocumentStatsExtension:
    """The ``builtin:document_stats`` report extension.

    :ivar name: The extension name, ``document_stats``.
    """

    name: Final[str] = EXTENSION_NAME

    def provide_run(self, model: Mapping) -> dict:
        """Return the worst documents by problem density, computed once per render (M18).

        :param model: The frozen run context.
        :returns: ``{"worst_documents": [...]}`` with at most :data:`WORST_DOCUMENTS`
            entries ``{path, bytes, problem_count, problem_count_per_kb}``, ordered by
            ``(-problem_count_per_kb, path)``.
        """
        worst = heapq.nsmallest(WORST_DOCUMENTS, _ranked(model["documents"]), key=lambda item: (item[0], item[1]))
        return {"worst_documents": [entry for _, _, entry in worst]}

    def provide_document(self, doc: Mapping, model: Mapping) -> dict:
        """Return the document's problem density (M34).

        :param doc: The frozen document mapping.
        :param model: The frozen run context (unused).
        :returns: ``{"problem_count_per_kb": Optional[float]}``.
        """
        return {"problem_count_per_kb": problem_count_per_kb(doc["problem_count"], doc["bytes"])}


def make(config: Config) -> DocumentStatsExtension:
    """Build the ``builtin:document_stats`` extension (the static-table factory).

    :param config: The effective configuration (unused; the calculation has no settings).
    :returns: The extension.
    """
    return DocumentStatsExtension()


__all__ = ["DENSITY_DIGITS", "WORST_DOCUMENTS", "DocumentStatsExtension", "make", "problem_count_per_kb"]
