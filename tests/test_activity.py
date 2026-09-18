"""Activity evidence: the System Log projection and the leaver checks that read it."""

import json
from datetime import date, datetime, timezone
from pathlib import Path

from access_review.models import ActivityEvent, ApiToken, App, Snapshot

FIXTURES = Path(__file__).parent.parent / "fixtures"

# Shaped like a real app.oauth2.credentials.lifecycle.create event, which is the
# worst case: Okta puts the new client secret in target[].detailEntry in plain
# text, and the event also carries the admin's address and location. The secret
# here is invented; never paste a real one into a test.
SECRET = "NOT-A-REAL-SECRET-abc123"
RAW_EVENT = {
    "uuid": "c6055d29-b2b9-11f1-929e-df99088ffd08",
    "published": "2026-09-02T14:12:03.613000Z",
    "eventType": "app.oauth2.credentials.lifecycle.create",
    "legacyEventType": "app.oauth2.credentials.lifecycle.create",
    "severity": "INFO",
    "displayMessage": "Create OAuth2 client credential",
    "actor": {"id": "u02", "type": "User", "displayName": "Marcus Lee", "alternateId": "marcus.lee@acme.example"},
    "outcome": {"result": "SUCCESS", "reason": None},
    "client": {
        "device": "Computer",
        "ipAddress": "203.0.113.42",
        "userAgent": {"browser": "CHROME", "os": "Mac OS X", "rawUserAgent": "Mozilla/5.0 ..."},
        "geographicalContext": {"city": "Naperville", "state": "Illinois", "country": "United States"},
    },
    "debugContext": {"debugData": {"clientId": "0oaBOT", "requestUri": "/api/v1/apps", "dtHash": "fbff0031"}},
    "securityContext": {"asNumber": 6079, "asOrg": "example-isp", "isProxy": False},
    "request": {"ipChain": [{"ip": "203.0.113.42", "version": "V4"}]},
    "transaction": {"id": "7f03125c", "type": "WEB"},
    "authenticationContext": {"externalSessionId": "102VjjX9AggTUymcUJCfqTkvw"},
    "target": [
        {
            "id": "0oaBOT",
            "type": "OAuth2ClientSecretEntity",
            "displayName": "Reporting Bot",
            "alternateId": "unknown",
            "detailEntry": {"clientid": "0oaBOT", "clientsecret": SECRET, "status": "active"},
        }
    ],
}


def test_projection_keeps_only_the_fields_checks_read():
    event = ActivityEvent.from_okta(RAW_EVENT)

    assert event.published == datetime(2026, 9, 2, 14, 12, 3, 613000, tzinfo=timezone.utc)
    assert event.event_type == "app.oauth2.credentials.lifecycle.create"
    assert event.actor_id == "u02"
    assert event.actor_type == "User"
    assert event.outcome == "SUCCESS"
    assert event.targets == [{"id": "0oaBOT", "type": "OAuth2ClientSecretEntity", "label": "Reporting Bot"}]


def test_no_secret_or_tracking_data_survives_into_a_snapshot():
    """The load-bearing one: a snapshot is written to disk and shared as evidence."""
    snapshot = Snapshot(
        org_url="https://acme.okta.com",
        collected_at=datetime(2026, 9, 15, tzinfo=timezone.utc),
        users=[],
        groups=[],
        apps=[],
        events=[ActivityEvent.from_okta(RAW_EVENT)],
    )

    written = json.dumps(snapshot.to_dict())

    assert SECRET not in written
    for leaked in ("clientsecret", "detailEntry", "debugContext", "securityContext", "ipAddress",
                   "geographicalContext", "rawUserAgent", "externalSessionId", "203.0.113.42"):
        assert leaked not in written, f"{leaked} reached the snapshot"


def test_an_event_missing_optional_parts_still_projects():
    """Hand-built and older events lack whole sections; none of them are required."""
    event = ActivityEvent.from_okta({"eventType": "user.session.start", "published": "2026-09-02T14:12:03.613Z"})

    assert event.actor_id == ""
    assert event.outcome == ""
    assert event.targets == []
    assert event.published is not None


def test_events_and_tokens_round_trip_through_a_snapshot():
    snapshot = Snapshot(
        org_url="https://acme.okta.com",
        collected_at=datetime(2026, 9, 15, tzinfo=timezone.utc),
        users=[],
        groups=[],
        apps=[App(id="a05", label="Reporting Bot", status="ACTIVE", service_client=True, client_id="0oaBOT")],
        api_tokens=[ApiToken(id="t1", name="ci-deploy", user_id="u02",
                             created=datetime(2026, 1, 4, tzinfo=timezone.utc))],
        events=[ActivityEvent.from_okta(RAW_EVENT)],
        activity_since=datetime(2026, 6, 17, tzinfo=timezone.utc),
    )

    again = Snapshot.from_dict(json.loads(json.dumps(snapshot.to_dict())))

    assert again.to_dict() == snapshot.to_dict()
    assert again.apps[0].client_id == "0oaBOT"
    assert again.tokens_for("u02")[0].name == "ci-deploy"
    assert again.tokens_for("u09") == []
    assert again.activity_since == snapshot.activity_since


def test_a_snapshot_saved_before_activity_existed_still_loads():
    old = {
        "org_url": "https://acme.okta.com",
        "collected_at": "2026-09-15T00:00:00Z",
        "users": [], "groups": [], "apps": [],
    }

    snapshot = Snapshot.from_dict(old)

    assert snapshot.events == []
    assert snapshot.api_tokens == []
    assert snapshot.activity_since is None


def test_events_for_actor_filters_and_orders_oldest_first():
    def at(day):
        return ActivityEvent(published=datetime(2026, 9, day, tzinfo=timezone.utc),
                             event_type="user.session.start", actor_id="u02")

    snapshot = Snapshot(
        org_url="https://acme.okta.com",
        collected_at=datetime(2026, 9, 15, tzinfo=timezone.utc),
        users=[], groups=[], apps=[],
        events=[at(12), ActivityEvent(published=None, event_type="user.session.start", actor_id="u09"), at(2)],
    )

    days = [e.published.day for e in snapshot.events_for_actor("u02")]

    assert days == [2, 12]


# --- the checks ------------------------------------------------------------

def _ctx(events=(), tokens=(), end_date="2026-08-29", status="terminated", user_status="ACTIVE",
         tz="America/Chicago"):
    from datetime import date

    from access_review.checks import Config, ReviewContext
    from access_review.models import Group, User
    from access_review.roster import RosterEntry, _parse_end

    user = User(id="u02", login="marcus.lee@acme.example", status=user_status,
                profile={"email": "marcus.lee@acme.example", "manager": "Priya", "department": "Eng"})
    snapshot = Snapshot(
        org_url="https://acme.okta.com",
        collected_at=datetime(2026, 9, 15, tzinfo=timezone.utc),
        users=[user],
        groups=[Group(id="g1", name="Finance", type="OKTA_GROUP", members={"u02"})],
        apps=[App(id="a05", label="Reporting Bot", status="ACTIVE", service_client=True, client_id="0oaBOT")],
        api_tokens=list(tokens),
        events=list(events),
    )
    config = Config(org_timezone=tz)
    ends, ends_at = _parse_end(end_date or "", config.timezone(), "marcus.lee@acme.example")
    roster = {"marcus.lee@acme.example": RosterEntry(
        "marcus.lee@acme.example", "Marcus Lee", "employee", status, ends, "Priya", end_at=ends_at)}
    return ReviewContext(snapshot, roster, config, date(2026, 9, 15))


def _findings(ctx, check_id):
    from access_review.checks import run_checks

    return [f for f in run_checks(ctx)[0] if f.check_id == check_id]


def _sso(day, actor="u02"):
    return ActivityEvent(published=datetime(2026, 9, day, 9, 0, tzinfo=timezone.utc),
                         event_type="user.authentication.sso", actor_id=actor,
                         targets=[{"id": "a02", "type": "AppInstance", "label": "Salesforce"}])


def test_a_sign_in_after_the_end_date_is_reported():
    [f] = _findings(_ctx(events=[_sso(2), _sso(12)]), "AR-13")

    assert f.severity == "critical"
    assert f.detail == "2 sign-ins after 2026-08-29; last 2026-09-12 (Salesforce)."


def test_the_end_date_is_their_last_working_day():
    """A sign-in on the day they left is them still working, not an incident."""
    on_the_day = ActivityEvent(published=datetime(2026, 8, 29, 23, 59, tzinfo=timezone.utc),
                               event_type="user.authentication.sso", actor_id="u02")

    assert _findings(_ctx(events=[on_the_day]), "AR-13") == []


def test_a_leaver_with_no_end_date_is_reported_as_undeterminable():
    [f] = _findings(_ctx(events=[_sso(2)], end_date=None), "AR-13")

    assert f.severity == "info"
    assert "no end date" in f.detail


def test_a_client_the_leaver_set_up_carries_their_activity():
    """The point of the check: the account is gone, the credential is not."""
    setup = ActivityEvent(published=datetime(2026, 5, 4, tzinfo=timezone.utc),
                          event_type="app.oauth2.credentials.lifecycle.create", actor_id="u02",
                          targets=[{"id": "0oaBOT", "type": "OAuth2ClientSecretEntity", "label": "Reporting Bot"}])
    grant = ActivityEvent(published=datetime(2026, 9, 14, tzinfo=timezone.utc),
                          event_type="app.oauth2.token.grant.access_token", actor_id="0oaBOT",
                          actor_type="PublicClientApp",
                          targets=[{"id": "AT.1", "type": "access_token", "label": "Reporting Bot"}])
    ctx = _ctx(events=[setup, grant], user_status="DEPROVISIONED")

    [credential] = _findings(ctx, "AR-12")
    [activity] = _findings(ctx, "AR-13")

    assert credential.detail == "Left 2026-08-29 but still holds API client they set up: Reporting Bot."
    assert activity.detail == "1 token grant after 2026-08-29; last 2026-09-14 (Reporting Bot)."


def test_a_deleted_client_is_not_reported():
    setup = ActivityEvent(published=datetime(2026, 5, 4, tzinfo=timezone.utc),
                          event_type="app.oauth2.credentials.lifecycle.create", actor_id="u02",
                          targets=[{"id": "0oaGONE", "type": "OAuth2ClientSecretEntity", "label": "Old Bot"}])

    assert _findings(_ctx(events=[setup]), "AR-12") == []


def test_tokens_and_clients_are_listed_together():
    setup = ActivityEvent(published=datetime(2026, 5, 4, tzinfo=timezone.utc),
                          event_type="app.oauth2.client.read_client_secret", actor_id="u02",
                          targets=[{"id": "0oaBOT", "type": "OAuth2Client", "label": "Reporting Bot"}])
    ctx = _ctx(events=[setup], tokens=[ApiToken(id="t1", name="ci-deploy", user_id="u02")])

    [f] = _findings(ctx, "AR-12")

    assert f.detail == ("Left 2026-08-29 but still holds API token ci-deploy; "
                        "API client they set up: Reporting Bot.")


def test_credentials_are_not_double_reported_as_residual_access():
    """AR-09 owns groups and apps; AR-12 owns credentials. They must not overlap."""
    ctx = _ctx(tokens=[ApiToken(id="t1", name="ci-deploy", user_id="u02")], user_status="DEPROVISIONED")

    assert "ci-deploy" not in _findings(ctx, "AR-09")[0].detail
    assert "Finance" not in _findings(ctx, "AR-12")[0].detail


def test_a_leaver_with_nothing_left_behind_is_clean():
    assert _findings(_ctx(), "AR-12") == []
    assert _findings(_ctx(), "AR-13") == []


def test_someone_still_employed_is_never_reported():
    ctx = _ctx(events=[_sso(12)], tokens=[ApiToken(id="t1", name="ci-deploy", user_id="u02")],
               status="active", end_date=None)

    assert _findings(ctx, "AR-12") == [] and _findings(ctx, "AR-13") == []


def test_an_expired_contractor_counts_as_a_leaver():
    """is_gone covers a passed end date, not just an HR termination."""
    ctx = _ctx(events=[_sso(12)], status="active", end_date="2026-06-30")

    assert _findings(ctx, "AR-13")[0].detail.endswith("after 2026-06-30; last 2026-09-12 (Salesforce).")


def test_no_findings_when_activity_was_never_collected():
    """Without the logs scope there are no events. Saying nothing is right here;
    the collector has already recorded the gap."""
    assert _findings(_ctx(events=[]), "AR-13") == []


# --- when access actually ended --------------------------------------------

def _at(when, tz_offset_hours):
    from datetime import timedelta
    return ActivityEvent(published=when.replace(tzinfo=timezone(timedelta(hours=tz_offset_hours))),
                         event_type="user.authentication.sso", actor_id="u02",
                         targets=[{"id": "a02", "type": "AppInstance", "label": "Salesforce"}])


def test_a_bare_end_date_gives_them_the_whole_last_day_in_the_org_timezone():
    """Resolving end-of-day in UTC flagged a US employee's last evening as an
    incident. The day belongs to the org's timezone, not the server's."""
    last_evening = _at(datetime(2026, 8, 29, 18, 0), -7)  # 6pm Pacific, still their last day

    assert _findings(_ctx(events=[last_evening]), "AR-13") == []


def test_the_next_morning_is_still_reported():
    assert _findings(_ctx(events=[_at(datetime(2026, 8, 30, 10, 0), -7)]), "AR-13") != []


def test_the_org_timezone_moves_the_boundary():
    """The same event, the same end date, two orgs. Sydney's last day ends earlier in UTC."""
    evening = _at(datetime(2026, 8, 29, 18, 0), -7)

    assert _findings(_ctx(events=[evening], tz="America/Chicago"), "AR-13") == []
    assert _findings(_ctx(events=[evening], tz="Australia/Sydney"), "AR-13") != []


def test_an_hr_timestamp_is_used_exactly():
    """The involuntary case: HR knows the minute access was meant to stop."""
    after = _at(datetime(2026, 8, 29, 16, 0), -5)  # 4pm CT, after the 2:05pm cutoff

    [f] = _findings(_ctx(events=[after], end_date="2026-08-29T14:05:00"), "AR-13")

    assert f.detail.startswith("1 sign-in after 2026-08-29 14:05 CDT;")


def test_activity_before_an_hr_timestamp_is_not_reported():
    before = _at(datetime(2026, 8, 29, 13, 0), -5)  # 1pm CT, before the 2:05pm cutoff

    assert _findings(_ctx(events=[before], end_date="2026-08-29T14:05:00"), "AR-13") == []


def test_a_timestamp_with_an_offset_keeps_it():
    from datetime import timedelta
    from zoneinfo import ZoneInfo

    from access_review.roster import _parse_end

    _, at = _parse_end("2026-08-29T22:30:00Z", ZoneInfo("America/Chicago"), "x@y.z")

    assert at.utcoffset() == timedelta(0)


def test_a_timestamp_without_an_offset_is_local_to_the_org():
    """Not UTC, and not whichever machine happens to run the review."""
    from zoneinfo import ZoneInfo

    from access_review.roster import _parse_end

    _, chicago = _parse_end("2026-08-29T17:30:00", ZoneInfo("America/Chicago"), "x@y.z")
    _, sydney = _parse_end("2026-08-29T17:30:00", ZoneInfo("Australia/Sydney"), "x@y.z")

    assert chicago != sydney


def test_a_bare_date_is_not_read_as_midnight():
    """datetime.fromisoformat accepts a date and returns 00:00, which would flag
    the whole last working day. The date parse has to be tried first."""
    from zoneinfo import ZoneInfo

    from access_review.roster import _parse_end

    assert _parse_end("2026-08-29", ZoneInfo("America/Chicago"), "x@y.z") == (date(2026, 8, 29), None)


def test_an_unreadable_end_date_names_the_row():
    import pytest
    from zoneinfo import ZoneInfo

    from access_review.roster import RosterError, _parse_end

    with pytest.raises(RosterError, match="bo@x.test.*'last tuesday'"):
        _parse_end("last tuesday", ZoneInfo("America/Chicago"), "bo@x.test")


def test_a_bad_roster_exits_cleanly_instead_of_crashing(tmp_path, capsys):
    from access_review import cli

    roster = tmp_path / "roster.csv"
    roster.write_text("email,status,end_date\nbo@x.test,terminated,last tuesday\n")

    code = cli.main(["--snapshot", str(FIXTURES / "demo_snapshot.json"), "--roster", str(roster),
                     "--out", str(tmp_path / "out"), "--no-email", "--no-slack"])

    assert code == 1
    assert "last tuesday" in capsys.readouterr().err


def test_an_unknown_org_timezone_is_rejected_at_config_load(tmp_path):
    import pytest

    from access_review.checks import Config

    path = tmp_path / "c.json"
    path.write_text('{"org_timezone": "Mars/Olympus"}')

    with pytest.raises(ValueError, match="Mars/Olympus"):
        Config.load(path)
