"""HR roster: the source of truth for who should have an account.

CSV columns: email, name, employment_type, status, end_date, manager
  employment_type: employee | contractor
  status:          active | leave | terminated
  end_date:        YYYY-MM-DD, or an ISO timestamp (termination date or
                   contract end), optional
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import date, datetime, time, tzinfo
from pathlib import Path


class RosterError(Exception):
    """A row the roster cannot be read from, named so the CLI can report it."""


@dataclass
class RosterEntry:
    email: str
    name: str
    employment_type: str
    status: str
    end_date: date | None
    manager: str
    # The moment access should have stopped, when HR recorded one. Without it
    # all we know is the day, and the day has to be resolved in a timezone.
    end_at: datetime | None = None

    def is_gone(self, as_of: date) -> bool:
        return self.status == "terminated" or (self.end_date is not None and self.end_date < as_of)

    def access_ends(self, tz: tzinfo) -> datetime | None:
        """The instant after which activity is activity by someone who has left.

        An exact time from HR is used as given. A bare date means the whole day
        was theirs to work, so it resolves to the end of that day in the org's
        timezone -- resolving it in UTC would flag a US employee's last evening
        as an incident, and hand an APAC one an extra day of cover.
        """
        if self.end_at:
            return self.end_at
        if self.end_date:
            return datetime.combine(self.end_date, time.max, tzinfo=tz)
        return None


def entry_for(roster: dict[str, RosterEntry] | None, email: str, login: str) -> RosterEntry | None:
    """Match an Okta user to their HR record. The collector and the checks both
    need this, and they have to agree on it."""
    if roster is None:
        return None
    return roster.get(email) or roster.get(login.lower())


def _parse_end(value: str, tz: tzinfo, email: str) -> tuple[date | None, datetime | None]:
    if not value:
        return None, None
    # Date first, and strictly: datetime.fromisoformat accepts a date-only
    # string and returns midnight, which would read a bare end_date as "access
    # stopped at 00:00" and flag their whole last working day.
    try:
        return date.fromisoformat(value), None
    except ValueError:
        pass
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise RosterError(
            f"{email}: end_date {value!r} is not a date (YYYY-MM-DD) or an ISO timestamp"
        ) from None
    # A time without an offset is local to the org, not to UTC or to whichever
    # machine runs the review.
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=tz)
    return moment.date(), moment


def load_roster(path: Path, tz: tzinfo) -> dict[str, RosterEntry]:
    entries = {}
    with path.open(newline="") as f:
        for row in csv.DictReader(f):
            email = row["email"].strip().lower()
            end_date, end_at = _parse_end((row.get("end_date") or "").strip(), tz, email)
            entries[email] = RosterEntry(
                email=email,
                name=(row.get("name") or "").strip(),
                employment_type=(row.get("employment_type") or "employee").strip().lower(),
                status=(row.get("status") or "active").strip().lower(),
                end_date=end_date,
                manager=(row.get("manager") or "").strip(),
                end_at=end_at,
            )
    return entries
