#!/usr/bin/env python3
"""Verify deployed intelligence refresh paths cannot drift from canonical CVEs."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEPLOY = ROOT / "deploy"
SYSTEMD = DEPLOY / "systemd"
WRAPPER = ROOT / "scripts" / "scheduled-canonical-source-refresh.sh"

text = WRAPPER.read_text(encoding="utf-8")
for needle in (
    "export-current-cves.py",
    'RBVM_CVSS_INPUT="$input"',
    'RBVM_EPSS_INPUT="$input"',
    'RBVM_KEV_INPUT="$input"',
    "RBVM_INTELLIGENCE_API_KEY",
    'PASS|PARTIAL|SKIPPED',
    'canonical_source_refresh=%s',
):
    if needle not in text:
        raise AssertionError(f"canonical source wrapper missing {needle!r}")

services = {
    "cvss": "rbvm-cvss-v31-refresh.service",
    "epss": "rbvm-epss-refresh.service",
    "kev": "rbvm-cisa-kev-refresh.service",
}
for source, name in services.items():
    service = (SYSTEMD / name).read_text(encoding="utf-8")
    expected = f"scheduled-canonical-source-refresh.sh {source}"
    if expected not in service:
        raise AssertionError(f"{name}: must derive the source input from canonical Cases")
    legacy = {
        "cvss": "scheduled-cvss-v31-refresh.sh",
        "epss": "scheduled-epss-refresh.sh",
        "kev": "scheduled-cisa-kev-refresh.sh",
    }[source]
    if "ExecStart=" in service and f"scripts/{legacy}" in service:
        raise AssertionError(f"{name}: must not run the static-input source script directly")
    if "canonical-intelligence-refresh" not in service:
        raise AssertionError(f"{name}: canonical-CVE staging path must be writable")

examples = (
    "cvss-v31-refresh.example",
    "epss-refresh.example",
    "cisa-kev-refresh.example",
)
for name in examples:
    example = (DEPLOY / name).read_text(encoding="utf-8")
    if "current-wazuh" in example or "RBVM_CVSS_INPUT=" in example \
            or "RBVM_EPSS_INPUT=" in example or "RBVM_KEV_INPUT=" in example:
        raise AssertionError(f"{name}: deployed source refresh must not pin a static CVE input")
    if "RBVM_API_BASE_URL=" not in example:
        raise AssertionError(f"{name}: canonical Cases API base must be explicit")

umbrella = (SYSTEMD / "rbvm-intelligence-refresh.timer").read_text(encoding="utf-8")
source_timers = (
    "rbvm-cvss-v31-refresh.timer",
    "rbvm-epss-refresh.timer",
    "rbvm-cisa-kev-refresh.timer",
)
for timer_name in source_timers:
    timer = (SYSTEMD / timer_name).read_text(encoding="utf-8")
    if "Conflicts=rbvm-intelligence-refresh.timer" not in timer:
        raise AssertionError(f"{timer_name}: must conflict with the umbrella schedule")
    if timer_name not in umbrella:
        raise AssertionError(f"umbrella timer must conflict with {timer_name}")

print("Intelligence refresh deployment checks: PASS")
