#!/usr/bin/env python3
"""Build PUBLIC_INTELLIGENCE_SYNC_BUNDLE_V1 from one exact acquisition artifact."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
BUILDER = ROOT / "scripts" / "build-public-intelligence-sync-bundle.py"
PROVIDERS = {"NVD", "FIRST_EPSS", "CISA_KEV", "CVE_PROGRAM"}
MODES = {"BOOTSTRAP", "INCREMENTAL"}


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("acquisition", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--previous-cves", type=Path)
    return parser.parse_args()


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_text(value, field):
    if not isinstance(value, str) or not value.strip():
        raise RuntimeError(f"acquisition {field} must be a non-blank string")
    return value.strip()


def load_acquisition(directory):
    if directory.is_symlink() or not directory.is_dir():
        raise RuntimeError("acquisition must be a non-symlink directory")
    descriptor_path = directory / "acquisition.json"
    if descriptor_path.is_symlink() or not descriptor_path.is_file():
        raise RuntimeError("acquisition.json must be a regular non-symlink file")
    try:
        descriptor = json.loads(descriptor_path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("acquisition.json must be valid UTF-8 JSON") from exc
    if not isinstance(descriptor, dict):
        raise RuntimeError("acquisition.json root must be an object")
    if descriptor.get("artifactType") != "PUBLIC_INTELLIGENCE_SOURCE_ACQUISITION":
        raise RuntimeError("unexpected acquisition artifactType")
    if descriptor.get("schemaVersion") != 1:
        raise RuntimeError("unsupported acquisition schemaVersion")

    provider = require_text(descriptor.get("provider"), "provider")
    mode = require_text(descriptor.get("syncMode"), "syncMode")
    if provider not in PROVIDERS:
        raise RuntimeError("unsupported acquisition provider")
    if mode not in MODES:
        raise RuntimeError("unsupported acquisition syncMode")
    source_uri = require_text(descriptor.get("sourceUri"), "sourceUri")
    if urlparse(source_uri).scheme != "https":
        raise RuntimeError("acquisition sourceUri must use HTTPS")
    source_version = require_text(descriptor.get("sourceVersion"), "sourceVersion")
    observed_at = require_text(descriptor.get("observedAt"), "observedAt")
    source_sha = require_text(descriptor.get("sourceSha256"), "sourceSha256").lower()
    source_file_name = require_text(descriptor.get("sourceFile"), "sourceFile")
    source_file = directory / source_file_name
    if source_file.parent.resolve() != directory.resolve():
        raise RuntimeError("acquisition sourceFile must be a direct child of the acquisition directory")
    if source_file.is_symlink() or not source_file.is_file():
        raise RuntimeError("acquisition sourceFile must be a regular non-symlink file")
    if sha256(source_file) != source_sha:
        raise RuntimeError("acquisition sourceFile SHA-256 does not match descriptor")

    published = descriptor.get("sourcePublishedAt", "")
    if published is None:
        published = ""
    if not isinstance(published, str):
        raise RuntimeError("acquisition sourcePublishedAt must be a string")
    return {
        "provider": provider,
        "mode": mode,
        "sourceUri": source_uri,
        "sourceVersion": source_version,
        "observedAt": observed_at,
        "sourcePublishedAt": published,
        "sourceFile": source_file,
    }


def main():
    args = arguments()
    acquisition = load_acquisition(args.acquisition.resolve())
    command = [
        sys.executable,
        str(BUILDER),
        acquisition["provider"],
        str(acquisition["sourceFile"]),
        str(args.output),
        "--mode",
        acquisition["mode"],
        "--source-uri",
        acquisition["sourceUri"],
        "--source-version",
        acquisition["sourceVersion"],
        "--observed-at",
        acquisition["observedAt"],
    ]
    if acquisition["sourcePublishedAt"]:
        command += ["--source-published-at", acquisition["sourcePublishedAt"]]
    if args.previous_cves:
        command += ["--previous-cves", str(args.previous_cves)]
    subprocess.run(command, cwd=ROOT, check=True)


if __name__ == "__main__":
    main()
