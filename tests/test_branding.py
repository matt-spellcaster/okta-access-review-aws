import json
from pathlib import Path

import pytest
from pypdf import PdfReader

from access_review.checks import Config
from access_review.cli import main
from access_review.pdf import Branding

FIXTURES = Path(__file__).parent.parent / "fixtures"


def pdf_text(out: Path) -> str:
    [run_dir] = list(out.iterdir())
    return "\n".join(p.extract_text() for p in PdfReader(run_dir / "report.pdf").pages)


def run_with_config(tmp_path, config: dict) -> tuple[int, Path]:
    cfg = tmp_path / "config.json"
    cfg.write_text(json.dumps(config))
    out = tmp_path / "out"
    code = main(["--snapshot", str(FIXTURES / "demo_snapshot.json"), "--config", str(cfg), "--out", str(out)])
    return code, out


def test_demo_config_is_branded():
    brand = Branding.from_config(Config.load(FIXTURES / "demo_config.json").branding)
    assert brand.enabled and brand.name == "Acme" and brand.logo == "acme"


def test_branded_pdf_shows_brand_on_every_page(tmp_path):
    code, out = run_with_config(tmp_path, {"branding": {"name": "Acme", "tagline": "Security & Compliance"}})
    assert code == 0
    [run_dir] = list(out.iterdir())
    pages = PdfReader(run_dir / "report.pdf").pages
    for page in pages:
        text = page.extract_text()
        assert "ACME" in text
        assert "CONFIDENTIAL · Acme" in text


def test_unbranded_pdf_is_plain(tmp_path):
    code, out = run_with_config(tmp_path, {})
    assert code == 0
    text = pdf_text(out)
    assert "ACME" not in text
    assert "CONFIDENTIAL · https://acme-demo.okta.com" in text


@pytest.mark.parametrize("branding, message", [
    ({"name": "X", "primary": "navy"}, "primary must be a #rrggbb"),
    ({"name": "X", "accent": "#12345"}, "accent must be a #rrggbb"),
    ({"name": "X", "logo": "vanta"}, "logo must be one of: acme"),
    ({"name": "X", "colour": "#000000"}, "unknown branding keys: colour"),
])
def test_bad_branding_fails_before_running(tmp_path, capsys, branding, message):
    code, out = run_with_config(tmp_path, {"branding": branding})
    assert code == 1
    assert message in capsys.readouterr().err
    assert not out.exists()
