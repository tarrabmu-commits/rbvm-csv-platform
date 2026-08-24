#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/collect-public-vulnerability-intel.py"
SOURCE = SCRIPT.read_text(encoding="utf-8")

for token in (
    "ThreadPoolExecutor",
    "DEFAULT_CVE_SERVICES_WORKERS = 6",
    "MAX_CVE_SERVICES_WORKERS = 12",
    "RBVM_CVE_SERVICES_WORKERS",
    "cve_services_worker_count",
    "as_completed",
    "atomic_write_bytes",
    "tempfile.mkstemp",
    "thread_name_prefix=\"rbvm-cve-services\"",
):
    if token not in SOURCE:
        raise AssertionError(f"enrichment performance guard missing {token}")

if 'cache_path.with_suffix(cache_path.suffix + ".tmp")' in SOURCE:
    raise AssertionError("shared provider cache must not use one fixed .tmp path")
if "delay = 0.7 if api_key else 6.1" not in SOURCE:
    raise AssertionError("NVD pacing contract drifted while optimizing CVE Services")

spec = importlib.util.spec_from_file_location("rbvm_public_intel", SCRIPT)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)

original_workers = os.environ.get("RBVM_CVE_SERVICES_WORKERS")
try:
    os.environ.pop("RBVM_CVE_SERVICES_WORKERS", None)
    if module.cve_services_worker_count(False) != 6:
        raise AssertionError("default CVE Services worker count drift")
    if module.cve_services_worker_count(True) != 1:
        raise AssertionError("offline collection must remain single-worker")
    os.environ["RBVM_CVE_SERVICES_WORKERS"] = "0"
    if module.cve_services_worker_count(False) != 1:
        raise AssertionError("worker count must clamp to at least one")
    os.environ["RBVM_CVE_SERVICES_WORKERS"] = "99"
    if module.cve_services_worker_count(False) != 12:
        raise AssertionError("worker count must clamp to the hard maximum")
    os.environ["RBVM_CVE_SERVICES_WORKERS"] = "not-an-int"
    try:
        module.cve_services_worker_count(False)
    except RuntimeError:
        pass
    else:
        raise AssertionError("invalid worker configuration must fail closed")

    active = 0
    peak = 0
    lock = threading.Lock()
    original_http_json = module.http_json

    def fake_http_json(url, cache_path, offline=False, headers=None, max_bytes=None):
        del cache_path, offline, headers, max_bytes
        nonlocal_state = None
        del nonlocal_state
        global active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        try:
            time.sleep(0.02)
            cve = url.rsplit("/", 1)[-1]
            payload = {"cveMetadata": {"cveId": cve}}
            raw = ("payload:" + cve).encode("utf-8")
            return payload, raw
        finally:
            with lock:
                active -= 1

    module.http_json = fake_http_json
    os.environ["RBVM_CVE_SERVICES_WORKERS"] = "4"
    cves = [f"CVE-2026-{10000 + index}" for index in range(12)]
    with tempfile.TemporaryDirectory(prefix="rbvm-cve-services-perf-") as temp:
        records, hashes = module.collect_cve_services(cves, Path(temp), False)
    module.http_json = original_http_json
    if set(records) != set(cves) or set(hashes) != set(cves):
        raise AssertionError("bounded CVE Services collection lost records or provenance hashes")
    if peak < 2 or peak > 4:
        raise AssertionError(f"bounded CVE Services concurrency not exercised correctly: peak={peak}")
finally:
    if original_workers is None:
        os.environ.pop("RBVM_CVE_SERVICES_WORKERS", None)
    else:
        os.environ["RBVM_CVE_SERVICES_WORKERS"] = original_workers

print("Public-intelligence enrichment performance checks: PASS")
