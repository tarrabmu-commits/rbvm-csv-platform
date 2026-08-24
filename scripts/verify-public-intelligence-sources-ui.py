#!/usr/bin/env python3
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
source_ui = ROOT / "src/main/resources/web/rbvm-ui.js"
integrator = ROOT / "scripts/integrate-public-intelligence-sources-ui.py"
compile_script = (ROOT / "scripts/compile.sh").read_text(encoding="utf-8")
status_handler = (ROOT / "src/main/java/io/rbvm/csv/PublicIntelligenceStatusHttpHandler.java").read_text(encoding="utf-8")
sync_handler = (ROOT / "src/main/java/io/rbvm/csv/PublicIntelligenceSyncHttpHandler.java").read_text(encoding="utf-8")
integration_source = integrator.read_text(encoding="utf-8")

assert "integrate-public-intelligence-sources-ui.py" in compile_script
assert "MutationObserver" not in integration_source
assert "window.fetch=" not in integration_source and "window.fetch =" not in integration_source
assert "scheduleAtFixedRate" not in integration_source

for forbidden in [
    "risk_score",
    "organizational_risk",
    "priority_tier",
    "sla_days",
    "customer_criticality",
]:
    assert forbidden not in integration_source.lower(), f"sources UI contains forbidden semantic {forbidden!r}"

with tempfile.TemporaryDirectory(prefix="rbvm-intelligence-sources-ui-") as tmp:
    generated = Path(tmp) / "rbvm-ui.js"
    shutil.copyfile(source_ui, generated)
    completed = subprocess.run(
        ["python3", str(integrator), str(generated)],
        check=True,
        capture_output=True,
        text=True,
    )
    assert "Public Intelligence Sources UI integration: PASS" in completed.stdout
    output = generated.read_text(encoding="utf-8")

for token in [
    "PUBLIC_INTELLIGENCE_SOURCES_UI_V1",
    "'/intelligence'",
    "'Intelligence Sources'",
    "'Update Intelligence Now'",
    "'/api/v1/intelligence/status'",
    "`/api/v1/intelligence/sync/${encodeURIComponent(provider)}`",
    "latestJob?.status === 'RUNNING'",
    "latest.status === 'FAILED'",
    "lastSuccess?.recordCount",
    "sourceSha256",
    "sourceVersion",
    "triggerSource",
    "errorCode",
    "errorDetail",
    "Status generated",
    "does not invent a stale threshold",
    "No failed start changes the last good local snapshot",
    "window.setTimeout",
    "1500",
    "else if(current==='/intelligence')await renderIntelligence()",
]:
    assert token in output, f"generated sources UI missing {token!r}"

assert output.count("['/intelligence', 'Intelligence', '◎']") == 1
assert "fake progress" not in output.lower()
assert "progress percentage" not in output.lower()
assert "stale after" not in output.lower()

for token in [
    'ROOT = "/api/v1/intelligence/status"',
    'response.put("generatedAt"',
    'value.put("latestJob"',
    'value.put("lastSuccess"',
    'success.put("recordCount"',
    'job.put("stage"',
    'job.put("errorCode"',
]:
    assert token in status_handler, f"status backend missing UI field {token!r}"

for token in [
    'ROOT = "/api/v1/intelligence/sync"',
    "ApiRole.OPERATOR",
    '"POST"',
    "INTELLIGENCE_SYNC_ALREADY_RUNNING",
]:
    assert token in sync_handler, f"sync backend missing UI contract {token!r}"

try:
    subprocess.run(
        ["python3", str(integrator), str(generated)],
        check=True,
        capture_output=True,
        text=True,
    )
    raise AssertionError("integration must fail closed when applied twice")
except subprocess.CalledProcessError:
    pass

print("Public Intelligence Sources UI V1 checks: PASS")
