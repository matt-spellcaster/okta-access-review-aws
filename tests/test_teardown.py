import json
import sys
from pathlib import Path

import pytest
from fakes import FakeS3

from access_review import store
from access_review.cli import main as review

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import teardown  # noqa: E402

FIXTURES = Path(__file__).parent.parent / "fixtures"
BUCKET = "uar-evidence-111122223333"


class Sts:
    def get_caller_identity(self):
        return {"Account": "111122223333"}


class Ssm:
    def __init__(self):
        self.deleted = []

    def delete_parameters(self, Names):
        self.deleted += Names


@pytest.fixture
def deployed(tmp_path):
    review(["--snapshot", str(FIXTURES / "demo_snapshot.json"), "--roster", str(FIXTURES / "demo_roster.csv"),
            "--config", str(FIXTURES / "demo_config.json"), "--as-of", "2026-09-15", "--out", str(tmp_path / "out"),
            "--no-email", "--no-slack"])
    [run_dir] = list((tmp_path / "out").iterdir())
    s3 = FakeS3()
    store.upload_run(s3, BUCKET, run_dir)
    return {"sts": Sts(), "s3": s3, "ssm": Ssm()}, run_dir.name


def test_dry_run_deletes_nothing(deployed, capsys):
    clients, _ = deployed
    before = dict(clients["s3"].objects)
    assert teardown.main([], clients) == 0
    assert clients["s3"].objects == before and clients["ssm"].deleted == []
    assert "Dry run" in capsys.readouterr().out


def test_the_wrong_account_stops_everything(deployed):
    clients, _ = deployed
    assert teardown.main(["--confirm-account", "999999999999"], clients) == 2
    assert clients["s3"].objects


def test_evidence_that_doesnt_verify_is_never_deleted(deployed, tmp_path, capsys):
    clients, run = deployed
    clients["s3"].objects[(BUCKET, f"runs/{run}/findings.csv")] = b"tampered"
    assert teardown.main(["--confirm-account", "111122223333", "--export-dir", str(tmp_path / "x")], clients) == 2
    assert clients["s3"].objects and clients["ssm"].deleted == []
    assert "findings.csv" in capsys.readouterr().err


def test_a_verified_export_then_empties_the_bucket(deployed, tmp_path):
    clients, run = deployed
    dest = tmp_path / "export"
    assert teardown.main(["--confirm-account", "111122223333", "--export-dir", str(dest)], clients) == 0
    assert json.loads((dest / run / "manifest.json").read_text())["files"]
    assert (tmp_path / "export.zip").exists()
    assert clients["s3"].objects == {}
    assert clients["s3"].deletes == [(BUCKET, True)]  # the only place retention is bypassed
    assert "/uar/okta/private_key" in clients["ssm"].deleted


class Tagging:
    def __init__(self, pages):
        self.pages = pages

    def get_resources(self, TagFilters, PaginationToken=None):
        assert TagFilters == [{"Key": "Project", "Values": ["okta-access-review"]}]
        i = int(PaginationToken or 0)
        page = {"ResourceTagMappingList": [{"ResourceARN": a} for a in self.pages[i]]}
        if i + 1 < len(self.pages):
            page["PaginationToken"] = str(i + 1)
        return page


class Iam:
    def __init__(self, roles=(), oidc=()):
        self.roles, self.oidc = list(roles), list(oidc)

    def list_roles(self, Marker=None):
        return {"Roles": [{"RoleName": r} for r in self.roles], "IsTruncated": False}

    def list_open_id_connect_providers(self):
        return {"OpenIDConnectProviderList": [{"Arn": a} for a in self.oidc]}


class ListS3:
    def __init__(self, names=()):
        self.names = names

    def list_buckets(self):
        return {"Buckets": [{"Name": n} for n in self.names]}

    def delete_objects(self, **kw):
        raise AssertionError("--check must never delete")


class ListSsm(Ssm):
    def __init__(self, names=()):
        super().__init__()
        self.names = names

    def describe_parameters(self, ParameterFilters):
        return {"Parameters": [{"Name": n} for n in self.names]}


def check_clients(tagged=((),), roles=(), oidc=(), buckets=(), params=()):
    return {"sts": Sts(), "tagging": Tagging(list(tagged)), "iam": Iam(roles, oidc), "s3": ListS3(buckets),
            "ssm": ListSsm(params)}


def test_check_passes_on_a_clean_account(capsys):
    clients = check_clients(roles=["AWSReservedSSO_AdministratorAccess_abc", "someone-else"],
                            buckets=["unrelated-bucket"])
    assert teardown.main(["--check"], clients) == 0
    assert "Nothing from this project is left" in capsys.readouterr().out


def test_check_lists_everything_left_and_deletes_nothing(capsys):
    clients = check_clients(
        tagged=[["arn:aws:lambda:us-east-1:111122223333:function:uar-collect"],
                ["arn:aws:s3:::uar-work-111122223333"]],
        roles=["uar-apply", "AWSReservedSSO_AdministratorAccess_abc"],
        oidc=["arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com"],
        buckets=["uar-tfstate-111122223333"],
        params=["/uar/okta/private_key"],
    )
    assert teardown.main(["--check"], clients) == 1
    out = capsys.readouterr().out
    for expected in ("function:uar-collect", "uar-work-111122223333", "IAM role: uar-apply",
                     "oidc-provider/token.actions", "S3 bucket: uar-tfstate", "/uar/okta/private_key"):
        assert expected in out
    assert "AWSReservedSSO" not in out
    assert clients["ssm"].deleted == []


def test_check_refuses_to_be_combined_with_a_delete():
    with pytest.raises(SystemExit):
        teardown.main(["--check", "--confirm-account", "111122223333"], check_clients())
