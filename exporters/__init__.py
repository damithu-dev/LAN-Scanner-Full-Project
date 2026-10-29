"""Exporters package for generating multi-format scan reports.

Each exporter is imported defensively: the Word (.docx) exporter needs the
optional ``python-docx`` package, and a missing optional dependency must not make
the CSV / JSON / XML / HTML exporters unusable. ``import exporters`` therefore
always succeeds and reports per-exporter availability through
:data:`EXPORTER_ERRORS`.
"""

from typing import Dict, Optional

EXPORTER_ERRORS: Dict[str, str] = {}

try:
    from exporters.csv_exporter import export_csv
except Exception as exc:  # pragma: no cover - depends on environment
    EXPORTER_ERRORS["csv"] = f"{type(exc).__name__}: {exc}"
    export_csv = None  # type: ignore[assignment]

try:
    from exporters.json_exporter import export_json
except Exception as exc:  # pragma: no cover
    EXPORTER_ERRORS["json"] = f"{type(exc).__name__}: {exc}"
    export_json = None  # type: ignore[assignment]

try:
    from exporters.xml_exporter import export_xml
except Exception as exc:  # pragma: no cover
    EXPORTER_ERRORS["xml"] = f"{type(exc).__name__}: {exc}"
    export_xml = None  # type: ignore[assignment]

try:
    from exporters.html_exporter import export_html
except Exception as exc:  # pragma: no cover
    EXPORTER_ERRORS["html"] = f"{type(exc).__name__}: {exc}"
    export_html = None  # type: ignore[assignment]

try:
    from exporters.word_exporter import export_word_report
except Exception as exc:  # pragma: no cover
    EXPORTER_ERRORS["word"] = (
        f"{type(exc).__name__}: {exc} (install it with: python -m pip install python-docx)"
    )
    export_word_report = None  # type: ignore[assignment]


def available_exporters() -> Dict[str, bool]:
    """Return a mapping of exporter name -> availability flag."""
    return {
        "csv": export_csv is not None,
        "json": export_json is not None,
        "xml": export_xml is not None,
        "html": export_html is not None,
        "word": export_word_report is not None,
    }


def unavailable_reason(name: str) -> Optional[str]:
    """Return why an exporter is unavailable, or None when it works."""
    return EXPORTER_ERRORS.get(name)


__all__ = [
    "export_json",
    "export_csv",
    "export_xml",
    "export_html",
    "export_word_report",
    "available_exporters",
    "unavailable_reason",
    "EXPORTER_ERRORS",
]
