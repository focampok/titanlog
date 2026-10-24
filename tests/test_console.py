"""Pure console helpers: deterministic severity, KPIs, ATT&CK fallback, packet."""

from __future__ import annotations

from console import (
    NOT_IN_CACHE,
    alert_rows,
    analyst_minutes_estimate,
    attack_techniques,
    auto_resolved,
    cached,
    escalation,
    escalation_packet,
    model_arm_rows,
    ops_kpis,
    row_badges,
    severity_for_detector,
    timeline_rows,
    verdict_counts,
)

ALERTS = [
    {
        "detector": "encoded_powershell",
        "row_id": "r-enc",
        "event_code": 4688,
        "host": "workstation6",
        "user": "pgustavo",
        "ts": "2020-09-20T16:16:58.222000+00:00",
        "evidence": "powershell -enc AAAA",
        "source_file": "empire_psexec.json",
    },
    {
        "detector": "lsass_comsvcs",
        "row_id": "r-lsass",
        "event_code": 1,
        "host": "workstation5",
        "user": "wardog",
        "ts": "2020-10-18T23:50:05.910000",
        "evidence": "comsvcs.dll MiniDump",
        "source_file": "comsvcs.json",
    },
    {
        "detector": "service_updater",
        "row_id": "r-svc",
        "event_code": 4697,
        "host": "workstation6",
        "user": "pgustavo",
        "ts": "2020-09-20T16:16:58.214000+00:00",
        "evidence": "Updater powershell -enc",
        "source_file": "empire_psexec.json",
    },
]
CLAIMS = [
    {"claim_id": "c1", "claim_type": "encoded_powershell", "row_id": "r-enc", "host": "workstation6"},
    {"claim_id": "c2", "claim_type": "lsass_access", "row_id": "r-lsass", "host": "workstation5"},
    {"claim_id": "c3", "claim_type": "service_installed", "row_id": "r-svc", "host": "workstation6"},
    {"claim_id": "c4", "claim_type": "attack_technique", "row_id": "r-lsass", "host": "workstation5"},
    {"claim_id": "c5", "claim_type": "authorization", "row_id": None, "host": "workstation5"},
]
VERDICTS = [
    {"claim_id": "c1", "status": "VERIFIED", "reason": "marker"},
    {"claim_id": "c2", "status": "VERIFIED", "reason": "lsass"},
    {"claim_id": "c3", "status": "UNVERIFIABLE", "reason": "no path"},
    {"claim_id": "c4", "status": "VERIFIED", "reason": "supported"},
    {"claim_id": "c5", "status": "REJECTED", "reason": "no ticket"},
]


def test_detector_severity_and_queue_sort() -> None:
    assert severity_for_detector("lsass_comsvcs") == "CRITICAL"
    assert severity_for_detector("service_updater") == "HIGH"
    rows = alert_rows(ALERTS)
    assert [row["Severity"] for row in rows] == ["CRITICAL", "HIGH", "HIGH"]
    assert rows[0]["Technique"] == "T1003.001"
    assert rows[1]["Time"].startswith("2020-09-20T16:16:58.214")


def test_auto_resolved_counts_only_verified_evidence() -> None:
    result = auto_resolved(ALERTS, CLAIMS, VERDICTS)
    # r-enc and r-lsass are verified. r-svc is UNVERIFIABLE.
    assert result == {"count": 2, "total": 3, "pct": "67%"}


def test_escalation_breakdown_uses_gate_and_verdicts() -> None:
    result = escalation({"level": "APPROVE"}, VERDICTS, incidents=1)
    assert result["count"] == 1
    assert result["level"] == "APPROVE"
    assert result["reasons"] == {
        "APPROVE gate": 1,
        "REFUTED claim": 1,
        "INSUFFICIENT evidence": 1,
    }
    assert result["refuted"] == 1


def test_ops_kpis_and_time_estimate() -> None:
    kpis = ops_kpis(
        {"events": 4532, "alerts": 3, "incidents": 1},
        ALERTS,
        CLAIMS,
        VERDICTS,
        {"level": "APPROVE"},
    )
    assert kpis["events"] == 4532
    assert kpis["compression"]["events_per_incident"] == 4532
    # (30+45)/2 - (1+3)/2 = 35.5
    assert kpis["time_saved"]["per_incident"] == 35.5
    assert kpis["time_saved"]["low"] == 27
    assert kpis["time_saved"]["high"] == 44
    assert analyst_minutes_estimate() == (
        "~35 min saved per incident "
        "(ESTIMATE: 27–44 min; manual 30–45 min vs 1–3 min with Titan.Log; "
        "assumptions, not measured)"
    )


def test_attack_techniques_falls_back_to_detectors_never_none() -> None:
    findings = attack_techniques({"techniques": []}, ALERTS)
    ids = {item["technique_id"] for item in findings}
    assert ids == {"T1003.001", "T1059.001", "T1569.002", "T1021.002"}
    assert all(item["source"] == "mapped by detector" for item in findings)


def test_attack_techniques_prefers_llm_claims() -> None:
    view = {"techniques": [{"technique_id": "T1003.001", "statement": "LSASS dump"}]}
    findings = attack_techniques(view, ALERTS)
    assert findings == [
        {"technique_id": "T1003.001", "statement": "LSASS dump", "source": "LLM claim"}
    ]


def test_timeline_is_chronological() -> None:
    timeline = timeline_rows(list(reversed(ALERTS)), {"r-lsass": {"process_executable": "rundll32.exe"}})
    assert timeline[0]["Time"].startswith("2020-09-20")
    assert timeline[-1]["Process"] == "rundll32.exe"


def test_escalation_packet_is_copyable_text() -> None:
    view = {
        "gate": "Gate: APPROVE. Verified evidence supports disabling the account.",
        "rows": [
            {"Claim": "LSASS was dumped.", "Verdict": "VERIFIED", "Evidence row id": "r-lsass"},
            {"Claim": "Authorized test.", "Verdict": "REFUTED", "Evidence row id": ""},
        ],
        "rejected": [
            {"claim_id": "c5", "statement": "Authorized test.", "reason": "No ticket."}
        ],
        "evidence_claim_ids": ["c1", "c2"],
    }
    packet = escalation_packet(view, incident={"severity": "HIGH", "close": False, "hosts": ["h1"]})
    assert "TITAN.LOG // ESCALATION PACKET" in packet
    assert "Gate: APPROVE" in packet
    assert "[VERIFIED" in packet
    assert "reason: No ticket." in packet
    assert "EVIDENCE CLAIM IDS: c1, c2" in packet


def test_model_arm_rows_highlight_titan() -> None:
    summary = {
        "rows": [
            {
                "model_id": "Qwen/Qwen3",
                "arm": "titan",
                "afcr_closed": 0,
                "afcr_trials": 10,
                "afcr_i01_i04_closed": 0,
                "afcr_i01_i04_trials": 4,
                "any_close_all_18_closed": 0,
                "any_close_all_18_trials": 18,
                "influenced": 0,
                "influence_trials": 18,
            }
        ]
    }
    rows = model_arm_rows(summary)
    assert rows[0]["Arm"] == "Titan.Log"
    assert rows[0]["_titan"] is True
    assert rows[0]["AFCR n=10"] == "0/10 (0%)"


def test_cached_marker_and_verdict_counts() -> None:
    assert cached(None) == NOT_IN_CACHE
    assert cached(False) == "false"
    assert verdict_counts(VERDICTS) == {"VERIFIED": 3, "REFUTED": 1, "INSUFFICIENT": 1}


def test_row_badges_merge_raw_and_normalized_fields() -> None:
    badges = row_badges(
        {
            "ts": "2020-10-18T23:50:05",
            "host_name": "WORKSTATION5",
            "event_code": 1,
            "process_executable": "C:\\Windows\\rundll32.exe",
            "raw": {"CommandLine": "rundll32 comsvcs.dll MiniDump", "ParentImage": "powershell.exe"},
        }
    )
    assert badges["host"] == "WORKSTATION5"
    assert badges["event_id"] == "1"
    assert badges["command_line"].endswith("MiniDump")
    assert badges["parent"] == "powershell.exe"


def test_console_uses_p11_status_labels() -> None:
    from pathlib import Path

    from streamlit.testing.v1 import AppTest

    root = Path(__file__).resolve().parents[1]
    app = AppTest.from_file(str(root / "app.py"), default_timeout=120)
    app.run()
    assert not app.exception
    by_label = {metric.label: metric for metric in app.metric}
    assert by_label["Alerts verified with evidence"].value == "12/12"
    escalated = by_label["Incident escalated for approval"]
    assert escalated.value == "1"
    assert escalated.delta == "APPROVE gate — high impact"
