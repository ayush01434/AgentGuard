from __future__ import annotations

import io
import json
import zipfile

import pytest
from fastapi.testclient import TestClient

import main
from codebase_scanner import scan_codebase_archive
from security_scanner import assess_compliance_evidence, calculate_cvss_v31

client = TestClient(main.app)


class _OSVResponse:
    def __init__(self, count: int):
        vuln = {
            "id": "GHSA-agentguard-test",
            "aliases": ["CVE-2025-12345"],
            "summary": "Mock advisory in unit-test fixture",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
            "references": [{"url": "https://osv.dev/vulnerability/GHSA-agentguard-test"}],
        }
        self.data = {"results": [{"vulns": [vuln]} for _ in range(count)]}

    def raise_for_status(self):
        return None

    def json(self):
        return self.data


class _OSVClient:
    async def post(self, url, json=None, headers=None):
        return _OSVResponse(len((json or {}).get("queries", [])))


def _make_zip(items: dict[str, bytes]) -> bytes:
    buff = io.BytesIO()
    with zipfile.ZipFile(buff, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in items.items():
            zf.writestr(name, content)
    return buff.getvalue()


def test_cvss_v31_base_score_calculator_and_invalid_vectors():
    report = calculate_cvss_v31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert report["baseScore"] == 9.8
    assert report["severity"] == "Critical"
    assert report["scoreType"] == "base_score"
    with pytest.raises(ValueError):
        calculate_cvss_v31("CVSS:3.1/AV:N/AC:L")
    with pytest.raises(ValueError):
        calculate_cvss_v31("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")


def test_compliance_assessment_reports_evidence_coverage_not_certification():
    report = assess_compliance_evidence(
        "Security policy is owned by the security team. MFA authentication is required. "
        "The incident response playbook is tested quarterly.",
        "nist_csf_2_0",
    )
    assert report["status"] == "COMPLETED"
    assert report["evidenceMentionedCount"] >= 2
    assert 0 <= report["evidenceCoveragePercent"] <= 100
    assert report["scoreType"] == "documented_evidence_coverage_not_compliance_score"
    assert any("not a formal compliance" in item.lower() for item in report["limitations"])


@pytest.mark.anyio
async def test_codebase_zip_scans_source_patterns_and_lock_manifests_without_extracting(tmp_path):
    archive = _make_zip({
        "repo/app.py": b"user_value = input()\nresult = eval(user_value)\n",
        "repo/requirements.txt": b"sample-lib==1.2.3\n",
        "repo/node_modules/vendor/unsafe.js": b"eval(x)\n",
        "../outside.py": b"eval(unsafe)\n",
    })
    report = await scan_codebase_archive("project.zip", archive, client=_OSVClient())
    assert report["status"] == "PARTIAL"
    assert report["sourceFilesScanned"] == 1
    assert report["packagesQueried"] == 1
    assert report["sourceFindingCount"] >= 1
    assert report["sourceCodeFindings"][0]["findingType"] == "heuristic_source_code_pattern"
    assert report["dependencyFindingCount"] == 1
    assert report["dependencyFindings"][0]["cvssV3BaseScore"] == 9.8
    assert not (tmp_path / "outside.py").exists()


def test_codebase_zip_rejects_non_zip_and_oversized_input():
    with pytest.raises(ValueError):
        import asyncio
        asyncio.run(scan_codebase_archive("project.tar.gz", b"not zip", client=_OSVClient()))


def test_cvss_api_requires_real_account_and_returns_base_score(monkeypatch, tmp_path):
    monkeypatch.setenv("AGENTGUARD_APP_DB_PATH", str(tmp_path / "cvss-test.db"))
    monkeypatch.setenv("AGENTGUARD_AUTH_SECRET", "test-secret-with-at-least-thirty-two-characters")
    main.AUTH_RATE_LIMIT_STORE.clear()
    created = client.post("/api/auth/signup", json={"name": "CVSS tester", "email": "cvss-api@example.test", "password": "Strong-password-123"})
    assert created.status_code == 201, created.text
    token = created.json()["access_token"]
    result = client.post(
        "/api/v1/security/cvss",
        headers={"Authorization": f"Bearer {token}"},
        json={"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    )
    assert result.status_code == 200, result.text
    assert result.json()["baseScore"] == 9.8
    assert result.json()["severity"] == "Critical"


def _new_auth_headers() -> dict[str, str]:
    import uuid
    email = f"advanced-security-{uuid.uuid4().hex}@example.test"
    response = client.post("/api/auth/signup", json={
        "name": "Advanced Security Test",
        "email": email,
        "password": "Strong-password-123",
    })
    assert response.status_code == 201, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def test_compliance_assessment_api_is_authenticated_and_reports_evidence_only():
    headers = _new_auth_headers()
    response = client.post(
        "/api/v1/security/compliance-assessment",
        headers=headers,
        json={"evidenceText": "The incident response plan is tested quarterly. MFA is enforced for admins."},
    )
    assert response.status_code == 200, response.text
    report = response.json()
    assert report["frameworkId"] == "nist_csf_2_0"
    assert 0 <= report["evidenceCoveragePercent"] <= 100
    assert report["scoreType"] == "documented_evidence_coverage_not_compliance_score"
    assert "not a formal compliance" in " ".join(report["limitations"]).lower()
    assert report["history"]["sessionId"] == report["sessionId"]


def test_codebase_scan_endpoint_uses_authenticated_route_and_saves_report(monkeypatch):
    headers = _new_auth_headers()

    async def fake_scan(filename: str, raw: bytes):
        assert filename == "agentguard-project.zip"
        assert raw == b"test zip bytes"
        return {
            "status": "PARTIAL",
            "archiveEntries": 2,
            "sourceFilesScanned": 1,
            "manifestCount": 1,
            "packagesQueried": 1,
            "sourceCodeFindings": [{"title": "Unsafe dynamic evaluation", "sourcePath": "app.py", "textLine": 2, "severity": "High", "cwe": "CWE-95", "evidence": "eval(<redacted>)", "remediation": "Avoid dynamic evaluation."}],
            "dependencyFindings": [],
            "findingCount": 1,
            "sourceFindingCount": 1,
            "dependencyFindingCount": 0,
            "limitations": ["Test fixture only."],
        }

    monkeypatch.setattr(main, "scan_codebase_archive", fake_scan)
    response = client.post(
        "/api/v1/security/codebase-scan",
        headers=headers,
        files={"file": ("agentguard-project.zip", b"test zip bytes", "application/zip")},
    )
    assert response.status_code == 200, response.text
    report = response.json()
    assert report["status"] == "PARTIAL"
    assert "Unsafe dynamic evaluation" in report["reportMarkdown"]
    assert report["history"]["sessionId"] == report["sessionId"]


def test_temporal_status_does_not_claim_workflow_when_temporal_is_disabled(monkeypatch):
    monkeypatch.setenv("AGENTGUARD_TEMPORAL_ENABLED", "false")
    response = client.get(
        "/api/v1/security/workflows/agentguard-analysis-0123456789abcdef0123456789abcdef",
        headers=_new_auth_headers(),
    )
    assert response.status_code == 503
    assert "Temporal execution is disabled" in response.json()["detail"]


@pytest.mark.parametrize(
    "statuses, expected",
    [
        ({"GOV-01": "implemented", "GOV-02": "partially_implemented"}, (1.5 / 13) * 100),
        ({"GOV-01": "implemented"}, (1.0 / 13) * 100),
    ],
)
def test_agentguard_baseline_score_is_fixed_denominator_and_transparent(statuses, expected):
    from security_scanner import score_agentguard_baseline
    report = score_agentguard_baseline([{"controlId": key, "status": value} for key, value in statuses.items()])
    assert report["scoreType"] == "agentguard_baseline_self_assessed_implementation_score"
    assert report["scorePercent"] == round(expected, 1)
    assert report["statusCounts"]["not_assessed"] == 11 if len(statuses) == 2 else 12
    assert "not an official NIST CSF score" in " ".join(report["limitations"])

def test_agentguard_baseline_n_a_requires_rationale_and_unknown_controls_rejected():
    from security_scanner import score_agentguard_baseline
    with pytest.raises(ValueError, match="rationale"):
        score_agentguard_baseline([{"controlId": "GOV-01", "status": "not_applicable"}])
    with pytest.raises(ValueError, match="Unknown"):
        score_agentguard_baseline([{"controlId": "MADE-UP", "status": "implemented"}])

def test_compliance_score_api_persists_self_assessment():
    headers = _new_auth_headers()
    response = client.post(
        "/api/v1/security/compliance-score",
        headers=headers,
        json={"assessments": [
            {"controlId": "GOV-01", "status": "implemented", "evidenceNote": "Approved security policy exists."},
            {"controlId": "PR-01", "status": "partially_implemented", "evidenceNote": "MFA is enabled for admins only."},
        ]},
    )
    assert response.status_code == 200, response.text
    report = response.json()
    assert report["frameworkId"] == "agentguard_baseline_v1"
    assert report["scorePercent"] == 11.5
    assert report["statusCounts"]["not_assessed"] == 11
    assert report["history"]["sessionId"] == report["sessionId"]
