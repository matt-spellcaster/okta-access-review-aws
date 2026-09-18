"""Review items: every piece of access the reviewer has to confirm, with a
proposed decision.

One item per app a person can reach (and by which route), per admin role they
hold, and per admin group they are in. Each carries a proposal, but proposals
are only proposals: the CISO, the single reviewer, confirms or overrides them
in Slack and then signs off on the result.

Proposals follow one rule for judgment calls -- revoke direct app access that
has not been used in `app_unused_days` -- and never propose revoking anything
on missing or incomplete data. When unsure, the item is left for a person to
decide.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import date, timedelta

from .checks import ReviewContext, app_usage_covers, records_sign_ins
from .models import App, User

KEEP, REVOKE, DECIDE = "keep", "revoke", "decide"
PROPOSALS = (KEEP, REVOKE, DECIDE)
# Reviewer roles. Every new item goes to the CISO; "admin" only appears in item
# files from reviews run before there was a single reviewer.
ADMIN, CISO = "admin", "ciso"
ITEMS_FILE = "review_items.json"
FORMAT = 1


class ItemsError(ValueError):
    pass


@dataclass(frozen=True)
class ReviewItem:
    key: str  # stable across runs for the same access, so decisions and tickets line up
    kind: str  # "app", "admin_role" or "admin_group"
    user_id: str
    user: str  # Okta login
    target_id: str
    target: str  # app label, role label or group name
    via: str  # "direct", "group:<name>" or "role"
    proposed: str  # keep, revoke or decide
    reason: str
    reviewer: str  # always ciso for new reviews

    @classmethod
    def from_dict(cls, d: dict) -> ReviewItem:
        item = cls(**{k: d[k] for k in cls.__dataclass_fields__})
        if item.proposed not in PROPOSALS or item.reviewer not in (ADMIN, CISO):
            raise ItemsError(f"item {item.key}: bad proposal or reviewer")
        return item


def item_key(kind: str, user_id: str, target_id: str, via: str) -> str:
    return hashlib.sha256(f"{kind}\x1f{user_id}\x1f{target_id}\x1f{via}".encode()).hexdigest()[:16]


def _app_proposal(ctx: ReviewContext, user: User, app: App, via: str) -> tuple[str, str]:
    cfg = ctx.config
    entry = ctx.roster_entry(user)
    if user.status == "DEPROVISIONED":
        return REVOKE, "Account is deactivated; remove so reactivating it doesn't restore access."
    if entry and entry.is_gone(ctx.as_of):
        when = f" ({entry.end_date})" if entry.end_date else ""
        return REVOKE, f"HR shows they have left{when}."
    if user.status == "SUSPENDED":
        return DECIDE, "Account is suspended; decide whether access should remain while it is."
    if ctx.is_service_account(user):
        return DECIDE, "Service account; its use doesn't show up as sign-ins."
    if not records_sign_ins(app):
        return DECIDE, "This app doesn't record sign-ins in Okta, so usage can't be checked."
    if app.label.lower() in {a.lower() for a in cfg.activity_exempt_apps}:
        return DECIDE, "This app is exempt from the usage rule in the config."
    if not app_usage_covers(ctx.snapshot, cfg.app_unused_days, ctx.as_of):
        return DECIDE, "App sign-in data is missing or incomplete for this review."

    cutoff = ctx.as_of - timedelta(days=cfg.app_unused_days)
    last = ctx.snapshot.last_app_sign_in(user.id, app.id)
    if last and last.date() >= cutoff:
        return KEEP, f"Signed in {last.date()}."
    unused = f"No sign-in in {cfg.app_unused_days} days"
    if via != "direct":
        return DECIDE, f"{unused}, but access comes from {via.removeprefix('group:')}; removing them from the group may change other access."
    assigned = app.assigned.get(user.id)
    if assigned is None:
        return DECIDE, f"{unused}; the assignment date is unknown."
    if assigned.date() >= cutoff:
        return KEEP, f"Assigned {assigned.date()}, less than {cfg.app_unused_days} days ago."
    return REVOKE, f"{unused} (assigned {assigned.date()})."


def build_items(ctx: ReviewContext) -> list[ReviewItem]:
    def item(kind: str, user: User, target_id: str, target: str, via: str, proposed: str, reason: str) -> ReviewItem:
        return ReviewItem(
            item_key(kind, user.id, target_id, via), kind, user.id, user.login,
            target_id, target, via, proposed, reason, CISO,
        )

    admin_groups = {n.lower() for n in ctx.config.admin_groups}
    items: list[ReviewItem] = []
    for user in sorted(ctx.snapshot.users, key=lambda u: u.login.lower()):
        for app, via in ctx.snapshot.apps_for(user.id):
            if app.service_client:
                continue
            items.append(item("app", user, app.id, app.label, via, *_app_proposal(ctx, user, app, via)))
        if user.status == "DEPROVISIONED":
            continue  # Okta drops admin roles on deactivation; AR-09 covers leftover groups
        for role in user.admin_roles or []:
            items.append(item("admin_role", user, role, role, "role", DECIDE, "Admin role; confirm it is still needed."))
        for group in ctx.snapshot.groups_for(user.id):
            if group.name.lower() in admin_groups:
                items.append(item(
                    "admin_group", user, group.id, group.name, "direct", DECIDE,
                    "Member of an admin group; confirm it is still needed.",
                ))

    keys = [i.key for i in items]
    if len(keys) != len(set(keys)):
        raise ItemsError("duplicate review item keys")
    return items


def items_json(items: list[ReviewItem], as_of: date, unused_days: int) -> str:
    return json.dumps(
        {"format": FORMAT, "review_date": as_of.isoformat(), "app_unused_days": unused_days,
         "items": [asdict(i) for i in items]},
        indent=2,
    ) + "\n"


def load_items(text: str) -> list[ReviewItem]:
    data = json.loads(text)
    if data.get("format") != FORMAT:
        raise ItemsError(f"unsupported {ITEMS_FILE} format {data.get('format')!r}")
    return [ReviewItem.from_dict(d) for d in data["items"]]


def summary(items: list[ReviewItem]) -> dict[str, int]:
    """Counts only, safe for a Slack channel or Step Functions output."""
    counts = {p: 0 for p in PROPOSALS}
    for i in items:
        counts[i.proposed] += 1
    counts["total"] = len(items)
    return counts
