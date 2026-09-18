"""Regenerate the README sample report and screenshots from the Acme demo data.

    uv run python scripts/render_samples.py

Only fixture data is used, never a live report.
"""

from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

import pypdfium2 as pdfium

from access_review.cli import main

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "fixtures"
DOCS = ROOT / "docs"
PAGES = 2  # page 3 is only the sign-off block
SCALE = 2  # 792pt-wide landscape page -> 1584px


def build_sample_pdf(out_dir: Path) -> Path:
    code = main([
        "--snapshot", str(FIXTURES / "demo_snapshot.json"),
        "--roster", str(FIXTURES / "demo_roster.csv"),
        "--config", str(FIXTURES / "demo_config.json"),
        "--as-of", "2026-09-15",
        "--out", str(out_dir),
        "--no-email",
    ])
    if code != 0:
        sys.exit(f"demo review failed with exit code {code}")
    [run_dir] = list(out_dir.iterdir())
    return run_dir / "report.pdf"


def render() -> None:
    (DOCS / "images").mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        pdf = build_sample_pdf(Path(tmp))
        shutil.copyfile(pdf, DOCS / "sample-report.pdf")
    doc = pdfium.PdfDocument(DOCS / "sample-report.pdf")
    try:
        for i in range(min(PAGES, len(doc))):
            image = doc[i].render(scale=SCALE).to_pil()
            path = DOCS / "images" / f"report-page-{i + 1}.png"
            image.save(path, optimize=True)
            print(f"wrote {path.relative_to(ROOT)} ({image.width}x{image.height})")
    finally:
        doc.close()
    print(f"wrote {(DOCS / 'sample-report.pdf').relative_to(ROOT)}")


if __name__ == "__main__":
    render()
