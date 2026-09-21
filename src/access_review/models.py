"""Normalized snapshot of an Okta org.

The collector turns Okta API responses into this shape, and fixtures use it
directly, so every check runs the same way against live or demo data.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

# Statuses where the account exists and can be (or become) usable.
LIVE_STATUSES = {"STAGED", "PROVISIONED", "ACTIVE", "RECOVERY", "PASSWORD_EXPIRED", "LOCKED_OUT"}
# Statuses where the user has actually been able to sign in.
SIGN_IN_STATUSES = {"ACTIVE", "RECOVERY", "PASSWORD_EXPIRED", "LOCKED_OUT"}
# Statuses where sign-in is blocked but the account and its access remain.
DISABLED_STATUSES = {"SUSPENDED", "DEPROVISIONED"}
# Built-in admin roles that can view but not change anything.
READ_ONLY_ROLES = {"read-only administrator", "report administrator"}
# App and OAuth client statuses. Okta words these differently from user
# statuses, and anything outside both sets is unknown, never assumed disabled.
APP_LIVE_STATUSES = {"ACTIVE"}
APP_DISABLED_STATUSES = {"INACTIVE"}

# System Log event types, grouped by what each one tells a review.
# Someone signed in, or used a session.
SIGN_IN_EVENTS = (
    "user.authentication.sso", "user.session.start",
    "user.authentication.verify", "user.session.access_admin_app",
)
# A credential was exchanged for access: an API client acting, or an app token.
TOKEN_EVENTS = ("app.oauth2.token.grant", "app.oauth2.authorize.code")
# A client's credentials were created, rotated or read. These say who set an
# API client up, which is the only record Okta keeps of who owns one.
CREDENTIAL_EVENTS = (
    "app.oauth2.client.lifecycle.create", "app.oauth2.credentials.lifecycle.",
    "app.oauth2.client.read_client_secret",
)


def parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def format_time(value: datetime | None) -> str | None:
    return value.isoformat().replace("+00:00", "Z") if value else None


@dataclass
class User:
    id: str
    login: str
    status: str
    created: datetime | None = None
    last_login: datetime | None = None
    profile: dict = field(default_factory=dict)
    # Enrolled factor types. None means unknown (not collected or not allowed).
    factors: list[str] | None = None
    # Admin role labels assigned directly to the user. None means unknown.
    admin_roles: list[str] | None = None

    @property
    def email(self) -> str:
        return (self.profile.get("email") or self.login).lower()

    @property
    def name(self) -> str:
        return f"{self.profile.get('firstName', '')} {self.profile.get('lastName', '')}".strip()

    @property
    def user_type(self) -> str:
        return (self.profile.get("userType") or "").strip()

    @property
    def manager(self) -> str:
        return (self.profile.get("manager") or "").strip()

    @property
    def department(self) -> str:
        return (self.profile.get("department") or "").strip()

    @classmethod
    def from_dict(cls, d: dict) -> User:
        return cls(
            id=d["id"],
            login=d["login"],
            status=d["status"],
            created=parse_time(d.get("created")),
            last_login=parse_time(d.get("lastLogin")),
            profile=d.get("profile", {}),
            factors=d.get("factors"),
            admin_roles=d.get("adminRoles"),
        )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "login": self.login,
            "status": self.status,
            "created": format_time(self.created),
            "lastLogin": format_time(self.last_login),
            "profile": self.profile,
            "factors": self.factors,
            "adminRoles": self.admin_roles,
        }


@dataclass
class Group:
    id: str
    name: str
    type: str
    members: set[str] = field(default_factory=set)

    @classmethod
    def from_dict(cls, d: dict) -> Group:
        return cls(id=d["id"], name=d["name"], type=d.get("type", "OKTA_GROUP"), members=set(d.get("members", [])))

    def to_dict(self) -> dict:
        return {"id": self.id, "name": self.name, "type": self.type, "members": sorted(self.members)}


@dataclass
class App:
    id: str
    label: str
    status: str
    sign_on_mode: str = ""
    users: set[str] = field(default_factory=set)  # directly assigned user IDs
    groups: set[str] = field(default_factory=set)  # assigned group IDs
    granted_scopes: list[str] = field(default_factory=list)  # Okta API scopes granted to the app
    admin_roles: list[str] = field(default_factory=list)  # admin roles assigned to the app's client
    # True for OAuth clients that act on their own authority (client_credentials),
    # as opposed to apps that act for a signed-in user.
    service_client: bool = False
    # The OAuth client_id, which is what System Log events name as the actor.
    client_id: str = ""
    # When each direct assignment in `users` was made. A user missing here has
    # an unknown assignment date, which is not the same as an old one.
    assigned: dict[str, datetime | None] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: dict) -> App:
        return cls(
            id=d["id"],
            label=d["label"],
            status=d.get("status", "ACTIVE"),
            sign_on_mode=d.get("signOnMode", ""),
            users=set(d.get("users", [])),
            groups=set(d.get("groups", [])),
            granted_scopes=list(d.get("grantedScopes", [])),
            admin_roles=list(d.get("adminRoles", [])),
            service_client=d.get("serviceClient", False),
            client_id=d.get("clientId", ""),
            assigned={k: parse_time(v) for k, v in (d.get("assigned") or {}).items()},
        )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "label": self.label,
            "status": self.status,
            "signOnMode": self.sign_on_mode,
            "users": sorted(self.users),
            "groups": sorted(self.groups),
            "grantedScopes": sorted(self.granted_scopes),
            "adminRoles": sorted(self.admin_roles),
            "serviceClient": self.service_client,
            "clientId": self.client_id,
            "assigned": {k: format_time(v) for k, v in sorted(self.assigned.items())},
        }


@dataclass
class ApiToken:
    """An Okta API token (SSWS). It keeps working until it is revoked or
    expires, whatever happens to the account of the user who owns it."""

    id: str
    name: str
    user_id: str
    created: datetime | None = None
    last_updated: datetime | None = None
    expires: datetime | None = None

    @classmethod
    def from_dict(cls, d: dict) -> ApiToken:
        return cls(
            id=d["id"],
            name=d.get("name", ""),
            user_id=d["userId"],
            created=parse_time(d.get("created")),
            last_updated=parse_time(d.get("lastUpdated")),
            expires=parse_time(d.get("expiresAt")),
        )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "userId": self.user_id,
            "created": format_time(self.created),
            "lastUpdated": format_time(self.last_updated),
            "expiresAt": format_time(self.expires),
        }


@dataclass
class ActivityEvent:
    """One System Log event, reduced to what the checks need."""

    published: datetime | None
    event_type: str
    actor_id: str
    actor_type: str = ""
    outcome: str = ""
    targets: list[dict] = field(default_factory=list)

    def is_kind(self, kinds: tuple[str, ...]) -> bool:
        """Match one of the groups above. Prefixes, because Okta subdivides:
        app.oauth2.token.grant also appears as .access_token and .refresh_token."""
        return self.event_type.startswith(kinds)

    @classmethod
    def from_okta(cls, raw: dict) -> ActivityEvent:
        """Project a raw System Log event onto the few fields checks read.

        This is an allowlist, not a filter, and it must stay one. Raw events
        carry secrets and far more personal data than a review needs --
        app.oauth2.credentials.lifecycle.create puts the new client secret in
        target[].detailEntry -- and a snapshot is written to disk and shared as
        evidence. Nothing outside the fields named here is ever copied.
        """
        actor = raw.get("actor") or {}
        return cls(
            published=parse_time(raw.get("published")),
            event_type=raw.get("eventType", ""),
            actor_id=actor.get("id", ""),
            actor_type=actor.get("type", ""),
            outcome=(raw.get("outcome") or {}).get("result", ""),
            targets=[
                {"id": t.get("id", ""), "type": t.get("type", ""), "label": t.get("displayName", "")}
                for t in raw.get("target") or []
            ],
        )

    @classmethod
    def from_dict(cls, d: dict) -> ActivityEvent:
        return cls(
            published=parse_time(d.get("published")),
            event_type=d["eventType"],
            actor_id=d.get("actorId", ""),
            actor_type=d.get("actorType", ""),
            outcome=d.get("outcome", ""),
            targets=list(d.get("targets", [])),
        )

    def to_dict(self) -> dict:
        return {
            "published": format_time(self.published),
            "eventType": self.event_type,
            "actorId": self.actor_id,
            "actorType": self.actor_type,
            "outcome": self.outcome,
            "targets": self.targets,
        }


@dataclass
class Snapshot:
    org_url: str
    collected_at: datetime
    users: list[User]
    groups: list[Group]
    apps: list[App]
    # Data the collector could not read, so the report can say what is incomplete.
    gaps: list[str] = field(default_factory=list)
    api_tokens: list[ApiToken] = field(default_factory=list)
    events: list[ActivityEvent] = field(default_factory=list)
    # Oldest point the activity evidence covers. None means activity was not
    # collected at all, which is not the same as "nothing happened".
    activity_since: datetime | None = None
    # Last sign-in to each app, as {(user_id, app_id): when}, from the System
    # Log's SSO events. app_usage_since is how far back that reaches; None means
    # usage was not collected at all. app_usage_complete is False when the log
    # read was cut short, so a missing entry cannot be read as "never used".
    app_usage: dict[tuple[str, str], datetime] = field(default_factory=dict)
    app_usage_since: datetime | None = None
    app_usage_complete: bool = True

    def last_app_sign_in(self, user_id: str, app_id: str) -> datetime | None:
        return self.app_usage.get((user_id, app_id))

    def groups_for(self, user_id: str) -> list[Group]:
        return [g for g in self.groups if user_id in g.members]

    def tokens_for(self, user_id: str) -> list[ApiToken]:
        return [t for t in self.api_tokens if t.user_id == user_id]

    def events_for_actor(self, actor_id: str) -> list[ActivityEvent]:
        """Every collected event this ID performed, oldest first."""
        matched = [e for e in self.events if e.actor_id == actor_id]
        return sorted(matched, key=lambda e: (e.published is None, e.published))

    def apps_for(self, user_id: str) -> list[tuple[App, str]]:
        """Apps a user can reach, with how: 'direct' or 'group:<name>'."""
        group_ids = {g.id: g.name for g in self.groups_for(user_id)}
        result = []
        for app in self.apps:
            if user_id in app.users:
                result.append((app, "direct"))
            for gid in sorted(app.groups & group_ids.keys()):
                result.append((app, f"group:{group_ids[gid]}"))
        return result

    @classmethod
    def from_dict(cls, d: dict) -> Snapshot:
        return cls(
            org_url=d["org_url"],
            collected_at=parse_time(d["collected_at"]),
            users=[User.from_dict(u) for u in d["users"]],
            groups=[Group.from_dict(g) for g in d["groups"]],
            apps=[App.from_dict(a) for a in d["apps"]],
            gaps=list(d.get("gaps", [])),
            api_tokens=[ApiToken.from_dict(t) for t in d.get("api_tokens", [])],
            events=[ActivityEvent.from_dict(e) for e in d.get("events", [])],
            activity_since=parse_time(d.get("activity_since")),
            app_usage={
                (u["userId"], u["appId"]): parse_time(u["lastSignIn"]) for u in d.get("app_usage", [])
            },
            app_usage_since=parse_time(d.get("app_usage_since")),
            app_usage_complete=d.get("app_usage_complete", True),
        )

    def to_dict(self) -> dict:
        return {
            "org_url": self.org_url,
            "collected_at": format_time(self.collected_at),
            "users": [u.to_dict() for u in self.users],
            "groups": [g.to_dict() for g in self.groups],
            "apps": [a.to_dict() for a in self.apps],
            "gaps": self.gaps,
            "api_tokens": [t.to_dict() for t in self.api_tokens],
            "events": [e.to_dict() for e in self.events],
            "activity_since": format_time(self.activity_since),
            "app_usage": [
                {"userId": uid, "appId": aid, "lastSignIn": format_time(when)}
                for (uid, aid), when in sorted(self.app_usage.items())
            ],
            "app_usage_since": format_time(self.app_usage_since),
            "app_usage_complete": self.app_usage_complete,
        }
