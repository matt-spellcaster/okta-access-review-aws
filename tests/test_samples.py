"""The README's sample report must match what the code generates today."""

import importlib.util
from pathlib import Path

ROOT = Path(__file__).parent.parent


def load_script():
    spec = importlib.util.spec_from_file_location("render_samples", ROOT / "scripts" / "render_samples.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_sample_pdf_is_up_to_date(tmp_path):
    fresh = load_script().build_sample_pdf(tmp_path)
    committed = ROOT / "docs" / "sample-report.pdf"
    assert committed.read_bytes() == fresh.read_bytes(), (
        "docs/sample-report.pdf is stale; run: uv run python scripts/render_samples.py"
    )


def test_readme_images_exist():
    readme = (ROOT / "README.md").read_text()
    for name in ("report-page-1.png", "report-page-2.png", "slack-summary.png"):
        assert f"docs/images/{name}" in readme
        assert (ROOT / "docs" / "images" / name).stat().st_size > 10_000
