#!/usr/bin/env python3
from pathlib import Path
import os
import subprocess

ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = ROOT / "scripts" / "run-server.sh"
README = ROOT / "README.md"
FRONTEND = ROOT / "docs" / "FRONTEND_SYSTEM_V2.md"


def run(*args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(LAUNCHER), *args],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


launcher = LAUNCHER.read_text(encoding="utf-8")

for marker in (
    "AUTH_FROM_ENV=false",
    "--auth-from-env",
    "--print-auth-mode",
    "export RBVM_AUTH_MODE=DISABLED",
    "unset RBVM_API_KEYS_FILE",
    "Local launcher authentication: DISABLED",
):
    if marker not in launcher:
        raise AssertionError(f"local launcher auth marker missing: {marker}")

# The trusted-local launcher must neutralize stale/inherited hardened auth settings.
hardened_env = os.environ.copy()
hardened_env["RBVM_AUTH_MODE"] = "API_KEY"
hardened_env["RBVM_API_KEYS_FILE"] = "/tmp/should-not-be-read-by-local-launcher"
local = run("--print-auth-mode", env=hardened_env)
if local.returncode != 0 or local.stdout.strip() != "DISABLED":
    raise AssertionError(
        "default local launcher must force DISABLED even when API_KEY is inherited; "
        f"rc={local.returncode} stdout={local.stdout!r} stderr={local.stderr!r}"
    )

# Hardened/auth tests remain possible, but only through an explicit opt-in flag.
hardened = run("--auth-from-env", "--print-auth-mode", env=hardened_env)
if hardened.returncode != 0 or hardened.stdout.strip() != "API_KEY":
    raise AssertionError(
        "--auth-from-env must preserve the explicitly supplied API_KEY mode; "
        f"rc={hardened.returncode} stdout={hardened.stdout!r} stderr={hardened.stderr!r}"
    )

# Explicit auth-from-env without a configured mode still follows backend default semantics.
plain_env = os.environ.copy()
plain_env.pop("RBVM_AUTH_MODE", None)
plain_env.pop("RBVM_API_KEYS_FILE", None)
plain = run("--auth-from-env", "--print-auth-mode", env=plain_env)
if plain.returncode != 0 or plain.stdout.strip() != "DISABLED":
    raise AssertionError("auth-from-env without RBVM_AUTH_MODE must resolve to DISABLED")

help_result = run("--help", env=hardened_env)
if help_result.returncode != 0 or "--auth-from-env" not in help_result.stdout:
    raise AssertionError("launcher help must document the hardened auth opt-in")

bad = run("--definitely-invalid", env=hardened_env)
if bad.returncode != 2 or "Unknown argument" not in bad.stderr:
    raise AssertionError("launcher must reject unknown arguments before starting the server")

readme = README.read_text(encoding="utf-8")
frontend = FRONTEND.read_text(encoding="utf-8")
for document, name in ((readme, "README"), (frontend, "Frontend contract")):
    for marker in ("./scripts/run-server.sh", "--auth-from-env"):
        if marker not in document:
            raise AssertionError(f"{name} must document local launcher auth behavior: {marker}")

print("Trusted-local launcher authentication checks: PASS")
