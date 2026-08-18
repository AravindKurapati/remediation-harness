"""Shared fixtures. Every test gets its own throwaway run directory."""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from harness.runstore import RunStore          # noqa: E402
from harness.record import new_record          # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture(scope="session", autouse=True)
def sandbox_library(tmp_path_factory):
    """Point the harness at a throwaway copy of the pattern library for the whole
    session. Tests write to the library (that IS the flywheel), and a suite that
    dirties tracked files is a suite people stop running."""
    import shutil
    sandbox = tmp_path_factory.mktemp("library")
    shutil.copytree(os.path.join(ROOT, "library"), str(sandbox), dirs_exist_ok=True)
    os.environ["RH_LIBRARY"] = str(sandbox)
    yield str(sandbox)
    os.environ.pop("RH_LIBRARY", None)


@pytest.fixture
def store(tmp_path):
    return RunStore.create(str(tmp_path), "R-test")


@pytest.fixture
def roles_file(tmp_path):
    p = tmp_path / "roles.yaml"
    p.write_text(
        "personas:\n"
        "  security_reviewer:\n"
        "    - priya@example.com\n"
        "    - both@example.com\n"
        "  portfolio_owner:\n"
        "    - sam@example.com\n"
        "    - both@example.com\n"
        "  governance_lead:\n"
        "    - dana@example.com\n"
        "  audit_viewer:\n"
        "    - auditor@example.com\n", encoding="utf-8")
    return str(p)


@pytest.fixture
def finding():
    return new_record(finding_id="FND-000001", source_scanner="semgrep",
                      source_rule_id="py.sqli.concat", repository="py-ledger",
                      portfolio="reporting", cwe="CWE-89", category="injection",
                      severity="high", title="SQL injection",
                      snippet='query = "SELECT * FROM a WHERE n = \'" + n + "\'"',
                      location={"file": "ledger/db.py", "line": 39, "symbol": None})
