from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from rosettalog.cli import app
from rosettalog.report import MigrationReport
from tests.conftest import EXAMPLES, FIXTURES

runner = CliRunner()
ACME = EXAMPLES / "acme_firewall"


def test_convert_writes_outputs_and_reports(tmp_path: Path) -> None:
    out = tmp_path / "out"
    result = runner.invoke(
        app,
        [
            "convert", str(ACME / "acme_fw.lsx.xml"), "--to", "sentinel", "--to", "splunk",
            "--sourcetype", "acme:firewall", "-s", str(ACME / "samples.yaml"), "-o", str(out),
        ],
    )  # fmt: skip
    assert result.exit_code == 0, result.output
    assert (out / "sentinel" / "acme_fw_lsx" / "AcmeFwLsxParser.kql").is_file()
    assert (out / "splunk" / "acme_fw_lsx" / "props.conf").is_file()
    report = MigrationReport.model_validate_json((out / "report.json").read_text())
    by_target = {t.target: t for t in report.artifacts[0].targets}
    assert by_target["sentinel"].status == "PARTIAL"
    assert by_target["sentinel"].verification.passed == 2
    assert by_target["splunk"].verification.passed == 4
    md = (out / "report.md").read_text()
    assert "RE2_NO_LOOKAROUND" in md
    assert "2/4 samples" in md


def test_strict_mode_fails_on_partial(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "convert",
            str(ACME / "acme_fw.lsx.xml"),
            "--to",
            "splunk",
            "-o",
            str(tmp_path),
            "--strict",
        ],
    )
    assert result.exit_code == 2


def test_verify_exit_codes() -> None:
    fails = runner.invoke(
        app,
        [
            "verify",
            str(ACME / "acme_fw.lsx.xml"),
            "-s",
            str(ACME / "samples.yaml"),
            "--to",
            "sentinel",
        ],
    )
    assert fails.exit_code == 2
    assert "UserName: qradar='bob.smith' sentinel=None" in fails.output
    passes = runner.invoke(
        app,
        [
            "verify",
            str(FIXTURES / "globex_vpn.lsx.xml"),
            "-s",
            str(FIXTURES / "globex_vpn.samples.yaml"),
            "--to",
            "sentinel",
        ],
    )
    assert passes.exit_code == 0, passes.output
    assert "4/4 samples match" in passes.output


def test_options_are_passed_to_backends(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "convert", str(ACME / "acme_fw.lsx.xml"), "--to", "sentinel", "-o", str(tmp_path),
            "-O", "sentinel.source_table=AcmeFw_CL", "-O", "sentinel.function_name=AcmeParser",
        ],
    )  # fmt: skip
    assert result.exit_code == 0, result.output
    kql = (tmp_path / "sentinel" / "acme_fw_lsx" / "AcmeParser.kql").read_text()
    assert "AcmeFw_CL" in kql
    assert "RawData" in kql


def test_unknown_target_and_missing_input(tmp_path: Path) -> None:
    bad = runner.invoke(
        app, ["convert", str(ACME / "acme_fw.lsx.xml"), "--to", "nope", "-o", str(tmp_path)]
    )
    assert bad.exit_code == 1
    assert "Unknown target 'nope'" in bad.output
    missing = runner.invoke(
        app, ["convert", "does-not-exist.xml", "--to", "splunk", "-o", str(tmp_path)]
    )
    assert missing.exit_code == 1


def test_non_lsx_input_is_reported_unsupported(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["convert", str(FIXTURES / "not_lsx.xml"), "--to", "splunk", "-o", str(tmp_path)]
    )
    assert result.exit_code == 0
    report = json.loads((tmp_path / "report.json").read_text())
    assert report["artifacts"][0]["targets"][0]["status"] == "UNSUPPORTED"


def test_directory_input(tmp_path: Path) -> None:
    result = runner.invoke(app, ["convert", str(FIXTURES), "--to", "sentinel", "-o", str(tmp_path)])
    assert result.exit_code == 0, result.output
    names = {a["name"] for a in json.loads((tmp_path / "report.json").read_text())["artifacts"]}
    assert {"globex_vpn.lsx", "edge_cases.lsx"} <= names


def test_inspect_plugins_schema() -> None:
    inspect = runner.invoke(app, ["inspect", str(ACME / "acme_fw.lsx.xml")])
    assert inspect.exit_code == 0
    assert json.loads(inspect.output)["parser"]["match_groups"][0]["order"] == 1
    plugins = runner.invoke(app, ["plugins"])
    assert "qradar-lsx" in plugins.output
    assert "sentinel" in plugins.output
    assert "splunk" in plugins.output
    schema = runner.invoke(app, ["schema"])
    assert json.loads(schema.output)["title"] == "MigrationReport"
