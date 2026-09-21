"""Email the PDF report over SMTP.

Settings come from the environment (see env.example). The body only has
counts and completeness; personal data stays in the attached PDF. TLS is
required: STARTTLS on port 587 (default) or implicit TLS on port 465.
"""

from __future__ import annotations

import hashlib
import os
import smtplib
import ssl
from collections import Counter
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import formatdate, make_msgid, parseaddr
from pathlib import Path
from urllib.parse import urlparse

from .checks import SEVERITIES, Finding
from .history import repeat_summary
from .models import Snapshot


class EmailConfigError(Exception):
    pass


def _address(value: str, name: str) -> str:
    value = value.strip()
    _, addr = parseaddr(value)
    if not addr or "@" not in addr or any(c in value for c in "\r\n"):
        raise EmailConfigError(f"{name} is not a valid email address: {value!r}")
    return value


@dataclass
class EmailSettings:
    host: str
    port: int
    username: str
    password: str
    sender: str
    recipients: list[str]

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> EmailSettings | None:
        """None when REPORT_EMAIL_TO is unset (email is off)."""
        env = os.environ if env is None else env
        to = env.get("REPORT_EMAIL_TO", "").strip()
        if not to:
            return None
        missing = [k for k in ("SMTP_HOST", "SMTP_USERNAME", "SMTP_PASSWORD", "REPORT_EMAIL_FROM") if not env.get(k)]
        if missing:
            raise EmailConfigError(f"REPORT_EMAIL_TO is set but these are missing: {', '.join(missing)}")
        port = int(env.get("SMTP_PORT", "587"))
        if port not in (465, 587):
            raise EmailConfigError(f"SMTP_PORT must be 587 (STARTTLS) or 465 (TLS), not {port}")
        return cls(
            host=env["SMTP_HOST"].strip(),
            port=port,
            username=env["SMTP_USERNAME"],
            password=env["SMTP_PASSWORD"],
            sender=_address(env["REPORT_EMAIL_FROM"], "REPORT_EMAIL_FROM"),
            recipients=[_address(r, "REPORT_EMAIL_TO") for r in to.split(",") if r.strip()],
        )


def build_message(
    settings: EmailSettings, snapshot: Snapshot, findings: list[Finding], run_dir: Path,
    gaps: list[str] | None = None,
) -> EmailMessage:
    """gaps spans every source the review read; snapshot.gaps speaks for Okta
    alone. Only the count goes in the body -- the gap strings name accounts."""
    pdf = run_dir / "report.pdf"
    counts = Counter(f.severity for f in findings)
    org = urlparse(snapshot.org_url).hostname or snapshot.org_url
    top = next((s for s in SEVERITIES if counts.get(s)), None)
    headline = f"{counts[top]} {top}" if top else "no findings"
    gaps = list(snapshot.gaps) if gaps is None else gaps
    status = "INCOMPLETE" if gaps else "complete"

    msg = EmailMessage()
    msg["Subject"] = f"Okta access review ({status}): {headline}, {org}"
    msg["From"] = settings.sender
    msg["To"] = ", ".join(settings.recipients)
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain=settings.sender.rsplit("@", 1)[-1].strip(">"))

    lines = [
        f"The Okta user access review for {org} has finished.",
        "",
        f"Status: {status}",
        f"Data collected: {snapshot.collected_at.strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        "Findings by severity:",
    ]
    lines += [f"  {s:<9}{counts.get(s, 0)}" for s in SEVERITIES]
    lines += [f"  {'total':<9}{len(findings)}", ""]
    if repeats := repeat_summary(findings):
        lines += [repeats, ""]
    if gaps:
        lines += [f"This review has {len(gaps)} data gap(s). See the report before relying on it.", ""]
    lines += [
        "Details, the access list and the sign-off page are in the attached PDF.",
        "The PDF contains personal data. Don't forward it outside the review team.",
        "",
        f"Report folder: {run_dir.name}",
        f"report.pdf SHA-256: {hashlib.sha256(pdf.read_bytes()).hexdigest()}",
        "(matches manifest.json in the report folder)",
    ]
    msg.set_content("\n".join(lines))
    msg.add_attachment(
        pdf.read_bytes(), maintype="application", subtype="pdf",
        filename=f"okta-access-review-{run_dir.name}.pdf",
    )
    return msg


def send(settings: EmailSettings, msg: EmailMessage, smtp_ssl=smtplib.SMTP_SSL, smtp=smtplib.SMTP) -> None:
    context = ssl.create_default_context()
    if settings.port == 465:
        server = smtp_ssl(settings.host, settings.port, context=context, timeout=30)
    else:
        server = smtp(settings.host, settings.port, timeout=30)
    with server:
        if settings.port != 465:
            server.ehlo()
            if not server.has_extn("starttls"):
                raise smtplib.SMTPNotSupportedError(f"{settings.host} does not offer STARTTLS; refusing to send")
            server.starttls(context=context)
            server.ehlo()
        server.login(settings.username, settings.password)
        server.send_message(msg)
