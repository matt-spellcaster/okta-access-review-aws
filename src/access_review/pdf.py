"""PDF version of the review for sharing and sign-off."""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import landscape, letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from . import __version__
from .checks import CHECKS, SEVERITIES, Finding
from .history import label
from .models import Snapshot

SEVERITY_COLORS = {
    "critical": colors.HexColor("#b42318"),
    "high": colors.HexColor("#c4320a"),
    "medium": colors.HexColor("#b54708"),
    "low": colors.HexColor("#475467"),
    "info": colors.HexColor("#1570ef"),
}
GRID = colors.HexColor("#d0d5dd")
MUTED_COLOR = colors.HexColor("#475467")
HEX = re.compile(r"^#[0-9a-fA-F]{6}$")
LOGOS = {"acme"}
BAND_HEIGHT = 0.6 * inch


@dataclass
class Branding:
    """Look of the PDF. Empty name means the plain, unbranded layout."""

    name: str = ""
    tagline: str = ""
    primary: str = "#101828"  # title, headings, header band
    accent: str = "#1570ef"  # logo tile and the rule under the band
    footer: str = "Confidential"
    logo: str = ""  # a built-in vector logo; no image files

    @classmethod
    def from_config(cls, data: dict) -> Branding:
        unknown = set(data) - set(cls.__dataclass_fields__)
        if unknown:
            raise ValueError(f"unknown branding keys: {', '.join(sorted(unknown))}")
        brand = cls(**data)
        for key in ("primary", "accent"):
            if not HEX.match(getattr(brand, key)):
                raise ValueError(f"branding.{key} must be a #rrggbb color, not {getattr(brand, key)!r}")
        if brand.logo and brand.logo not in LOGOS:
            raise ValueError(f"branding.logo must be one of: {', '.join(sorted(LOGOS))}")
        return brand

    @property
    def enabled(self) -> bool:
        return bool(self.name)


def _tint(hex_color: str, amount: float) -> colors.Color:
    """Mix a color with white; amount=0.9 is a very light tint."""
    c = colors.HexColor(hex_color)
    return colors.Color(*(v + (1 - v) * amount for v in (c.red, c.green, c.blue)))


def draw_acme_logo(canvas, x: float, y: float, size: float, accent, ink=colors.white) -> None:
    """Rounded tile with a geometric 'A': two legs, a crossbar and a notch."""
    s = size
    canvas.saveState()
    canvas.setFillColor(accent)
    canvas.roundRect(x, y, s, s, radius=s * 0.22, stroke=0, fill=1)
    canvas.setFillColor(ink)
    path = canvas.beginPath()
    for i, (px, py) in enumerate([
        (0.50, 0.84), (0.82, 0.16), (0.65, 0.16), (0.50, 0.50), (0.35, 0.16), (0.18, 0.16),
    ]):
        (path.moveTo if i == 0 else path.lineTo)(x + px * s, y + py * s)
    path.close()
    canvas.drawPath(path, stroke=0, fill=1)
    canvas.rect(x + 0.33 * s, y + 0.28 * s, 0.34 * s, 0.08 * s, stroke=0, fill=1)
    canvas.restoreState()


class _Theme:
    def __init__(self, brand: Branding):
        self.brand = brand
        base = getSampleStyleSheet()
        primary = colors.HexColor(brand.primary)
        self.title = ParagraphStyle("title", parent=base["Title"], alignment=0, fontSize=20, spaceAfter=4,
                                    textColor=primary)
        self.h2 = ParagraphStyle("h2", parent=base["Heading2"], spaceBefore=14, spaceAfter=6, keepWithNext=1,
                                 textColor=primary)
        self.body = ParagraphStyle("body", parent=base["BodyText"], fontSize=9, leading=12)
        self.small = ParagraphStyle("small", parent=self.body, fontSize=8, leading=10)
        self.muted = ParagraphStyle("muted", parent=self.small, textColor=MUTED_COLOR)
        self.warn = ParagraphStyle("warn", parent=self.body, textColor=SEVERITY_COLORS["critical"])
        self.cell_bold = ParagraphStyle("cellbold", parent=self.small, fontName="Helvetica-Bold",
                                        textColor=primary if brand.enabled else colors.black)
        self.header_bg = _tint(brand.primary, 0.9) if brand.enabled else colors.HexColor("#f2f4f7")

    def p(self, text, style: ParagraphStyle | None = None) -> Paragraph:
        return Paragraph(escape(str(text)), style or self.small)

    def table(self, rows: list[list], widths: list[float]) -> Table:
        table = Table(rows, colWidths=widths, repeatRows=1, hAlign="LEFT")
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), self.header_bg),
            ("GRID", (0, 0), (-1, -1), 0.5, GRID),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        return table

    def severity(self, severity: str) -> Paragraph:
        color = SEVERITY_COLORS.get(severity, colors.black).hexval()[2:]
        return Paragraph(f'<font color="#{color}"><b>{escape(severity.upper())}</b></font>', self.small)

    def page_decor(self, org_url: str):
        brand = self.brand

        def draw(canvas, doc):
            width, height = doc.pagesize
            canvas.saveState()
            if brand.enabled:
                canvas.setFillColor(colors.HexColor(brand.primary))
                canvas.rect(0, height - BAND_HEIGHT, width, BAND_HEIGHT, stroke=0, fill=1)
                canvas.setFillColor(colors.HexColor(brand.accent))
                canvas.rect(0, height - BAND_HEIGHT - 3, width, 3, stroke=0, fill=1)
                text_x = doc.leftMargin
                logo = 0.36 * inch
                if brand.logo == "acme":
                    draw_acme_logo(canvas, doc.leftMargin, height - BAND_HEIGHT + (BAND_HEIGHT - logo) / 2, logo,
                                   colors.HexColor(brand.accent))
                    text_x += logo + 0.14 * inch
                canvas.setFillColor(colors.white)
                canvas.setFont("Helvetica-Bold", 15)
                name_y = height - BAND_HEIGHT / 2 - (1 if brand.tagline else 5)
                canvas.drawString(text_x, name_y, brand.name.upper())
                if brand.tagline:
                    canvas.setFont("Helvetica", 7.5)
                    canvas.setFillColor(_tint(brand.primary, 0.7))
                    canvas.drawString(text_x, name_y - 11, brand.tagline)
                canvas.setFillColor(colors.white)
                canvas.setFont("Helvetica", 9)
                canvas.drawRightString(width - doc.rightMargin, height - BAND_HEIGHT / 2 - 3,
                                       "Okta user access review")
            canvas.setFont("Helvetica", 7.5)
            canvas.setFillColor(MUTED_COLOR)
            left = " · ".join(p for p in (brand.footer.upper(), brand.name, org_url) if p)
            canvas.drawString(doc.leftMargin, 0.4 * inch, left)
            canvas.drawRightString(width - doc.rightMargin, 0.4 * inch, f"Page {doc.page}")
            canvas.restoreState()

        return draw


def write_pdf(
    path: Path,
    snapshot: Snapshot,
    findings: list[Finding],
    skipped: list[str],
    as_of: date,
    matrix: list[dict],
    branding: Branding | None = None,
    roster_label: str = "not provided",
    history_note: str = "",
    gaps: list[str] | None = None,
    sources: list | None = None,
) -> Path:
    # Passed in, not derived: write_report computes both once so the PDF's
    # Status row and the manifest's signed `complete` flag cannot disagree.
    # Defaults keep a snapshot-only caller honest about Okta's own gaps.
    gaps = list(snapshot.gaps) if gaps is None else gaps
    sources = sources or []
    brand = branding or Branding()
    t = _Theme(brand)
    doc = SimpleDocTemplate(
        str(path),
        pagesize=landscape(letter),
        leftMargin=0.5 * inch,
        rightMargin=0.5 * inch,
        topMargin=BAND_HEIGHT + 0.3 * inch if brand.enabled else 0.5 * inch,
        bottomMargin=0.6 * inch,
        title=f"{brand.name} Okta user access review".strip(),
        author=f"okta-access-review {__version__}",
        invariant=1,  # no embedded timestamps, so identical input gives identical bytes
    )
    width = doc.width
    counts = Counter(f.severity for f in findings)
    story: list = []

    story.append(Paragraph("Okta user access review", t.title))
    live = sum(1 for u in snapshot.users if u.status != "DEPROVISIONED")
    meta = [
        ["Org", snapshot.org_url],
        ["Data collected", snapshot.collected_at.strftime("%Y-%m-%d %H:%M UTC")],
        ["Review date", as_of.isoformat()],
        ["Scope", f"{len(snapshot.users)} users ({live} not deprovisioned), "
                  f"{len(snapshot.groups)} groups, {len(snapshot.apps)} apps"],
        ["HR roster", roster_label],
        *[["Also read", f"{s.source} ({s.principals} principals, read {s.collected_at[:10]})"] for s in sources],
        ["Status", "INCOMPLETE, see data gaps" if gaps else "Complete"],
        ["Tool", f"okta-access-review {__version__} (read-only)"],
    ]
    meta_table = Table(
        [[t.p(k, t.cell_bold), t.p(v)] for k, v in meta], colWidths=[1.3 * inch, width - 1.3 * inch], hAlign="LEFT"
    )
    meta_table.setStyle(TableStyle([
        ("BOTTOMPADDING", (0, 0), (-1, -1), 1),
        ("TOPPADDING", (0, 0), (-1, -1), 1),
        ("LEFTPADDING", (0, 0), (0, -1), 0),
    ]))
    story.append(meta_table)

    story.append(Paragraph("Summary", t.h2))
    summary = [[t.p("Severity", t.cell_bold)] + [t.severity(s) for s in SEVERITIES] + [t.p("Total", t.cell_bold)]]
    summary.append([t.p("Findings", t.cell_bold)] + [t.p(counts.get(s, 0)) for s in SEVERITIES] + [t.p(len(findings))])
    story.append(t.table(summary, [1.2 * inch] + [0.9 * inch] * len(SEVERITIES) + [0.9 * inch]))
    if skipped:
        story.append(Spacer(1, 4))
        story.append(t.p(f"Skipped (needs data this run did not have): {', '.join(skipped)}", t.muted))

    if gaps:
        story.append(Paragraph("Data gaps", t.h2))
        story.append(t.p("This review is incomplete. Fix these before relying on it:", t.warn))
        for gap in gaps:
            story.append(t.p(f"• {gap}", t.body))

    story.append(Paragraph("Findings", t.h2))
    if findings:
        titles = {c.id: c.title for c in CHECKS}
        headers = ("Severity", "Check", "Subject", "Detail") + (("History",) if history_note else ())
        rows = [[t.p(h, t.cell_bold) for h in headers]]
        for f in findings:
            row = [t.severity(f.severity), t.p(f"{f.check_id} {titles[f.check_id]}"), t.p(f.subject), t.p(f.detail)]
            rows.append(row + [t.p(label(f))] if history_note else row)
        if history_note:
            story.append(t.p(history_note, t.muted))
            story.append(Spacer(1, 4))
            widths = [0.8 * inch, 2.0 * inch, 2.0 * inch, width - 6.4 * inch, 1.6 * inch]
        else:
            widths = [0.8 * inch, 2.2 * inch, 2.2 * inch, width - 5.2 * inch]
        story.append(t.table(rows, widths))
    else:
        story.append(t.p("No findings.", t.body))

    used = {f.check_id for f in findings}
    rows = [[t.p(h, t.cell_bold) for h in ("Check", "Controls", "Fix")]]
    for c in CHECKS:
        if c.id in used:
            rows.append([t.p(f"{c.id} {c.title}"), t.p(", ".join(c.controls)), t.p(c.remediation)])
    if len(rows) > 1:
        story.append(Paragraph("Remediation and control mapping", t.h2))
        story.append(t.table(rows, [2.6 * inch, 2.6 * inch, width - 5.2 * inch]))

    story.append(Paragraph("Access by user", t.h2))
    story.append(t.p("Full detail, including apps, is in access_matrix.csv. Record decisions there.", t.muted))
    story.append(Spacer(1, 4))
    headers = ("Login", "Status", "Type", "Manager", "Last sign-in", "MFA", "Admin roles", "Groups")
    rows = [[t.p(h, t.cell_bold) for h in headers]]
    for r in matrix:
        rows.append([t.p(r["login"]), t.p(r["status"]), t.p(r["type"]), t.p(r["manager"]), t.p(r["last_login"]),
                     t.p(r["mfa"]), t.p(r["admin_roles"]), t.p(r["groups"])])
    story.append(t.table(rows, [2.0 * inch, 1.15 * inch, 0.8 * inch, 1.05 * inch, 0.85 * inch, 1.25 * inch,
                                1.3 * inch, width - 8.4 * inch]))

    sign = Table(
        [["", "", ""], [t.p("Reviewer name", t.muted), t.p("Signature", t.muted), t.p("Date", t.muted)]],
        colWidths=[width / 3] * 3,
        rowHeights=[20, 14],
        hAlign="LEFT",
    )
    sign.setStyle(TableStyle([("LINEABOVE", (0, 1), (-1, 1), 0.75, colors.black), ("RIGHTPADDING", (0, 0), (-1, -1), 18)]))
    story.append(KeepTogether([
        Paragraph("Reviewer sign-off", t.h2),
        t.p("I reviewed the findings and the access list above and recorded a decision for each user.", t.body),
        Spacer(1, 18),
        sign,
    ]))

    decor = t.page_decor(snapshot.org_url)
    doc.build(story, onFirstPage=decor, onLaterPages=decor)
    return path
