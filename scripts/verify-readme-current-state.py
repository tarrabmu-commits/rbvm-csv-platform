#!/usr/bin/env python3
"""Keep top-level project state aligned with implemented contracts."""

from pathlib import Path

readme = (Path(__file__).resolve().parents[1] / "README.md").read_text(encoding="utf-8")

for needle in (
    "Database migrations: **V1–V22**",
    "`RBVM_DECISION_INPUT_SNAPSHOT_V3`",
    "Formula readiness and golden-case contracts exist",
    "Current Canonical Cases",
    "rbvm-intelligence-refresh.timer",
    "Formula result          = Priority / SLA / Treatment",
):
    if needle not in readme:
        raise AssertionError(f"README current-state contract missing {needle!r}")

for stale in (
    "Database migrations: **V1–V20**",
    "PostgreSQL V20 stores typed Decision Input V2",
    "next core methodology work starts with **Formula Readiness",
):
    if stale in readme:
        raise AssertionError(f"README contains stale platform state {stale!r}")

print("README current-state checks: PASS")
