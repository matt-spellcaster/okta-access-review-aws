"""The service account register: who is accountable for a credential nobody logs in as.

Grown from `Config.service_accounts`, which was a flat list of logins meaning
only "expected to be missing from the HR roster" (AR-03). An entry now carries
an owner, so declaring an account is an ownership claim a person's name is on,
not a way to make a finding go quiet.

In the config file an entry is either a bare string, which is the old form and
means declared with nobody named, or an object:

    "service_accounts": [
      "svc-legacy@acme.example",
      {"id": "Terraform Automation", "owner": "priya.shah@acme.example",
       "purpose": "Applies infrastructure changes from CI", "reviewed": "2026-07-01"},
      {"source": "github:acme-eng", "id": "acme-ci-bot", "purpose": "Release automation"}
    ]

`id` is the name a person writes: an Okta login, an Okta service client's app
label, a GitHub member's login. Deliberately not the stable principal id that
`graph_subject` uses -- a register is a human artifact maintained by hand, and
nobody knows an account as `0oa1f2e3d4`. The cost is that a rename breaks the
entry, and the way it breaks is the point: the account stops being declared, so
the finding comes back at full severity and the projection records a gap naming
the entry that matched nothing. A register that has drifted says so rather than
quietly vouching for an account that no longer exists.

`owner` is an identity key -- the lowercased email `identity.identity_key`
builds from an Okta profile -- because that is what the graph joins on. An
entry with an owner links the account to that person, which puts it on their
access review and in their departure bundle if they leave. An entry without one
is *declared but unattributed*: somebody wrote it down and named nobody, which
is weaker evidence than a link and stronger than nothing, and is its own branch
of AR-15 rather than an absence of one.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date

# `identity.okta.OKTA`, repeated rather than imported: the identity layer
# imports this module to read the register, so importing it back would be a
# cycle. `test_the_default_source_is_the_identity_layers_okta_name` pins them
# together.
OKTA = "okta"

FIELDS = frozenset({"id", "source", "owner", "purpose", "reviewed"})


class RegisterError(ValueError):
    """A register entry that cannot be read, named so the CLI can report it.

    A ValueError as well, because `Config.load` already raises that for a bad
    config and every caller of it is written to catch it.
    """


@dataclass(frozen=True)
class ServiceAccount:
    """One declared account, and who answers for it."""

    id: str
    source: str = OKTA
    # An identity key, or "" for an entry that names nobody. Never a display
    # name: this is joined against, and a link to a person who does not exist
    # reports a credential as accounted for when nobody is.
    owner: str = ""
    purpose: str = ""
    # When someone last confirmed this entry is still true. Carried into the
    # link's evidence rather than checked here: an ownership claim from three
    # years ago is worth less than a fresh one, and an auditor reading the
    # bundle should be able to see which they are looking at.
    reviewed: date | None = None

    @property
    def key(self) -> tuple[str, str]:
        return (self.source, self.id.lower())

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "source": self.source,
            "owner": self.owner,
            "purpose": self.purpose,
            "reviewed": self.reviewed.isoformat() if self.reviewed else "",
        }

    def evidence(self) -> str:
        """What the link says. Read by a person deciding whether to trust it, so
        it names the claim, the claimant and when it was last checked."""
        parts = ["declared a service account in the review register"]
        parts.append(f"owned by {self.owner}" if self.owner else "with no owner recorded")
        if self.purpose:
            parts.append(self.purpose)
        if self.reviewed:
            parts.append(f"last reviewed {self.reviewed.isoformat()}")
        return ", ".join(parts)


@dataclass(frozen=True)
class Register:
    entries: tuple[ServiceAccount, ...] = ()

    def __len__(self) -> int:
        return len(self.entries)

    def entry(self, source: str, name: str) -> ServiceAccount | None:
        """The entry declaring this account, or None. Matched case-insensitively
        on the name within one source: an Okta login and a GitHub login that
        happen to be the same string are two different accounts, and declaring
        one must never declare the other."""
        return self._index.get((source, name.lower()))

    def for_source(self, source: str) -> list[ServiceAccount]:
        return [e for e in self.entries if e.source == source]

    def stale(self, source: str, matched: set[tuple[str, str]]) -> list[str]:
        """Gaps for this source's entries that matched no account in it.

        Recorded rather than ignored. An entry names an account by a name a
        person typed, so a rename, a typo or a deleted account leaves a claim
        that looks like coverage and is not: the account it meant to vouch for
        is undeclared again and reported at full severity, while whoever wrote
        the entry believes it is handled. Saying so is the difference between a
        register that is maintained and one that is merely long.
        """
        missing = sorted(e.id for e in self.for_source(source) if e.key not in matched)
        if not missing:
            return []
        return [
            f"The service account register declares {len(missing)} account(s) in {source} that the "
            f"read did not return: {', '.join(missing)}. Each was renamed, removed, or never "
            f"spelled this way, so nothing is declared by those entries."
        ]

    def to_dict(self) -> list[dict]:
        """The register as the manifest records it.

        `report.write_report` signs the config it ran under, so this is evidence
        an auditor reads: which accounts were declared, by whom, and when the
        claim was last checked. `dataclasses.asdict` would do all of it except
        `reviewed`, which is a date and not JSON.
        """
        return [e.to_dict() for e in self.entries]

    def __post_init__(self) -> None:
        # Indexed once, not per lookup: a projection asks this for every user in
        # the estate, so rebuilding the dict each time is O(users x entries) on
        # the one path that has to fit in a 1024 MB Lambda. Set rather than
        # declared, so it stays out of `asdict` -- its keys are tuples, and the
        # manifest this config is written into is JSON.
        object.__setattr__(self, "_index", {e.key: e for e in self.entries})

    @classmethod
    def from_config(cls, raw: object) -> Register:
        if isinstance(raw, Register):  # already parsed; Config() built in code
            return raw
        if not isinstance(raw, list):
            raise RegisterError(f"service_accounts must be a list, not {type(raw).__name__}")
        entries = [_entry(item, n) for n, item in enumerate(raw, start=1)]
        seen: dict[tuple[str, str], ServiceAccount] = {}
        for entry in entries:
            clash = seen.get(entry.key)
            if clash is not None:
                # Not last-wins: two entries for one account are two ownership
                # claims, and the register is meant to be the answer to who owns
                # it. Picking one silently would make the register itself the
                # ambiguity it exists to remove.
                raise RegisterError(
                    f"service_accounts declares {entry.source}/{entry.id} twice "
                    f"(owners {clash.owner or 'none'!r} and {entry.owner or 'none'!r}); "
                    f"one account has one owner"
                )
            seen[entry.key] = entry
        return cls(entries=tuple(entries))


def _entry(item: object, n: int) -> ServiceAccount:
    where = f"service_accounts entry {n}"
    if isinstance(item, str):
        # The old flat-list form, still read so an existing config keeps
        # working. It declares the account and names nobody, which is exactly
        # what the flat list always meant -- now it is reported as that rather
        # than as ownership.
        if not item.strip():
            raise RegisterError(f"{where} is empty")
        return ServiceAccount(id=item.strip())
    if not isinstance(item, dict):
        raise RegisterError(f"{where} must be a login or an object, not {type(item).__name__}")
    unknown = set(item) - FIELDS
    if unknown:
        raise RegisterError(f"{where}: unknown keys: {', '.join(sorted(unknown))}")
    name = str(item.get("id", "")).strip()
    if not name:
        raise RegisterError(f"{where} has no id")
    source = str(item.get("source") or OKTA).strip()
    if not source:
        raise RegisterError(f"{where} ({name}) has an empty source")
    return ServiceAccount(
        id=name,
        source=source,
        # Normalised the way `identity.identity_key` normalises an Okta profile
        # email, because that is the key this is joined against. Left as typed,
        # `Alice@Acme.Example` would link to nobody and the account would read
        # as owned while reaching no one's review.
        owner=str(item.get("owner") or "").strip().lower(),
        purpose=str(item.get("purpose") or "").strip(),
        reviewed=_reviewed(item.get("reviewed"), where, name),
    )


def _reviewed(value: object, where: str, name: str) -> date | None:
    if value in (None, ""):
        return None
    try:
        return date.fromisoformat(str(value))
    except ValueError:
        raise RegisterError(
            f"{where} ({name}): reviewed {value!r} is not a date (YYYY-MM-DD)"
        ) from None
