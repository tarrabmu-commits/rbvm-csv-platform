#!/usr/bin/env python3
"""Acquire one exact official source payload for LOCAL_PUBLIC_INTELLIGENCE_STORE_V1."""

import argparse
from datetime import date, datetime, timezone
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
from urllib.parse import urlparse
from urllib.request import Request, urlopen
import zipfile

NVD_BASE = "https://nvd.nist.gov/feeds/json/cve/2.0"
FIRST_EPSS = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
CISA_KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CVE_COMMIT_API = "https://api.github.com/repos/CVEProject/cvelistV5/commits/main"
CVE_ARCHIVE = "https://github.com/CVEProject/cvelistV5/archive/{sha}.zip"

NVD_FEED_RE = re.compile(r"^(modified|20[0-9]{2})$")
SHA256_RE = re.compile(r"^[A-Fa-f0-9]{64}$")
EPSS_MODEL_RE = re.compile(r"^v?[0-9]{4}\.[0-9]{2}\.[0-9]{2}$")

MAX_META_BYTES = 64 * 1024
MAX_NVD_COMPRESSED = 128 * 1024 * 1024
MAX_NVD_UNCOMPRESSED = 2 * 1024 * 1024 * 1024
MAX_EPSS_COMPRESSED = 64 * 1024 * 1024
MAX_EPSS_UNCOMPRESSED = 192 * 1024 * 1024
MAX_CISA_BYTES = 32 * 1024 * 1024
MAX_GITHUB_API_BYTES = 2 * 1024 * 1024
MAX_CVE_ARCHIVE_BYTES = 2 * 1024 * 1024 * 1024

USER_AGENT = "rbvm-csv-platform/0.23 local-public-intelligence-source-acquisition"


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("provider", choices=["NVD", "FIRST_EPSS", "CISA_KEV", "CVE_PROGRAM"])
    parser.add_argument("output", type=Path, help="new or empty acquisition directory")
    parser.add_argument("--nvd-feed", help="NVD feed identity: modified or a year >= 2002")
    parser.add_argument("--observed-at", help="fixed ISO-8601 time for deterministic tests")
    parser.add_argument(
        "--offline-input",
        type=Path,
        help="validate local source bytes instead of performing network acquisition",
    )
    parser.add_argument(
        "--offline-metadata",
        type=Path,
        help="NVD .meta or CVE Program commit JSON for deterministic offline validation",
    )
    return parser.parse_args()


def utc_now(value):
    if not value:
        return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RuntimeError("--observed-at must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise RuntimeError("--observed-at must include timezone")
    return parsed.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def iso_timestamp(value, field, *, assume_utc=False):
    text = str(value or "").strip()
    if not text:
        raise RuntimeError(f"{field} is required")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RuntimeError(f"{field} must be ISO-8601") from exc
    if parsed.tzinfo is None:
        if not assume_utc:
            raise RuntimeError(f"{field} must include timezone")
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def require_regular(path, field):
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"{field} must be a regular non-symlink file")


def prepare_output(path):
    if path.is_symlink():
        raise RuntimeError("output directory must not be a symlink")
    if path.exists():
        if not path.is_dir() or any(path.iterdir()):
            raise RuntimeError("output directory must not exist or must be empty")
    else:
        path.mkdir(parents=True)


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def bounded_local_copy(source, target, maximum):
    require_regular(source, "--offline-input")
    size = source.stat().st_size
    if size <= 0 or size > maximum:
        raise RuntimeError("offline source is empty or exceeds configured maximum")
    shutil.copyfile(source, target)
    return size


def request_headers(accept):
    headers = {"Accept": accept, "User-Agent": USER_AGENT}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def allowed_final_host(url, allowed_hosts):
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in allowed_hosts:
        raise RuntimeError("official source redirect left the HTTPS host allowlist")


def fetch_bytes(url, target, maximum, *, accept, allowed_hosts):
    request = Request(url, headers=request_headers(accept))
    with urlopen(request, timeout=120) as response:  # nosec: fixed/derived official HTTPS URLs
        if response.status != 200:
            raise RuntimeError(f"official source returned HTTP {response.status}")
        allowed_final_host(response.geturl(), allowed_hosts)
        length = response.headers.get("Content-Length")
        if length:
            try:
                if int(length) > maximum:
                    raise RuntimeError("official source Content-Length exceeds configured maximum")
            except ValueError as exc:
                raise RuntimeError("official source Content-Length is invalid") from exc
        written = 0
        with target.open("wb") as handle:
            while True:
                chunk = response.read(min(1024 * 1024, maximum - written + 1))
                if not chunk:
                    break
                written += len(chunk)
                if written > maximum:
                    raise RuntimeError("official source exceeds configured maximum")
                handle.write(chunk)
    if written <= 0:
        raise RuntimeError("official source is empty")
    return written


def fetch_text(url, maximum, *, allowed_hosts):
    with tempfile.TemporaryDirectory(prefix="rbvm-source-text-") as temp:
        path = Path(temp) / "source.txt"
        fetch_bytes(
            url,
            path,
            maximum,
            accept="text/plain, application/json",
            allowed_hosts=allowed_hosts,
        )
        try:
            return path.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            raise RuntimeError("official metadata must be UTF-8") from exc


def write_descriptor(output, descriptor):
    path = output / "acquisition.json"
    temporary = output / ".acquisition.json.tmp"
    temporary.write_text(
        json.dumps(descriptor, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    temporary.replace(path)


def parse_nvd_meta(text):
    values = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        values[key.strip()] = value.strip()
    required = {"lastModifiedDate", "size", "gzSize", "sha256"}
    if not required.issubset(values):
        raise RuntimeError("NVD META is missing required fields")
    try:
        size = int(values["size"])
        gz_size = int(values["gzSize"])
    except ValueError as exc:
        raise RuntimeError("NVD META sizes must be integers") from exc
    if size <= 0 or size > MAX_NVD_UNCOMPRESSED:
        raise RuntimeError("NVD META uncompressed size is invalid or too large")
    if gz_size <= 0 or gz_size > MAX_NVD_COMPRESSED:
        raise RuntimeError("NVD META compressed size is invalid or too large")
    sha = values["sha256"].lower()
    if not SHA256_RE.fullmatch(sha):
        raise RuntimeError("NVD META sha256 is invalid")
    return {
        "lastModifiedDate": iso_timestamp(values["lastModifiedDate"], "NVD lastModifiedDate"),
        "size": size,
        "gzSize": gz_size,
        "sha256": sha,
    }


def verify_nvd_gzip(path, meta):
    compressed_size = path.stat().st_size
    if compressed_size != meta["gzSize"]:
        raise RuntimeError(
            f"NVD GZip size mismatch: expected {meta['gzSize']}, got {compressed_size}"
        )
    digest = hashlib.sha256()
    size = 0
    try:
        with gzip.open(path, "rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_NVD_UNCOMPRESSED:
                    raise RuntimeError("NVD decompressed source exceeds configured maximum")
                digest.update(chunk)
    except (OSError, EOFError) as exc:
        raise RuntimeError("NVD source is not a valid complete gzip stream") from exc
    if size != meta["size"]:
        raise RuntimeError(f"NVD uncompressed size mismatch: expected {meta['size']}, got {size}")
    if digest.hexdigest() != meta["sha256"]:
        raise RuntimeError("NVD uncompressed SHA-256 does not match META")


def acquire_nvd(args, output, observed_at):
    feed = args.nvd_feed or "modified"
    if not NVD_FEED_RE.fullmatch(feed):
        raise RuntimeError("--nvd-feed must be modified or a year >= 2002")
    if feed != "modified" and int(feed) < 2002:
        raise RuntimeError("NVD year feed must be 2002 or later")
    stem = f"nvdcve-2.0-{feed}"
    meta_url = f"{NVD_BASE}/{stem}.meta"
    source_url = f"{NVD_BASE}/{stem}.json.gz"
    if args.offline_input:
        if not args.offline_metadata:
            raise RuntimeError("NVD offline mode requires --offline-metadata")
        require_regular(args.offline_metadata, "--offline-metadata")
        meta_text = args.offline_metadata.read_text(encoding="utf-8")
    else:
        meta_text = fetch_text(meta_url, MAX_META_BYTES, allowed_hosts={"nvd.nist.gov"})
    meta = parse_nvd_meta(meta_text)
    source = output / "source.json.gz"
    if args.offline_input:
        bounded_local_copy(args.offline_input, source, MAX_NVD_COMPRESSED)
    else:
        fetch_bytes(
            source_url,
            source,
            MAX_NVD_COMPRESSED,
            accept="application/gzip, application/octet-stream",
            allowed_hosts={"nvd.nist.gov"},
        )
    verify_nvd_gzip(source, meta)
    return {
        "provider": "NVD",
        "syncMode": "INCREMENTAL" if feed == "modified" else "BOOTSTRAP",
        "sourceFile": source.name,
        "sourceUri": source_url,
        "metadataUri": meta_url,
        "sourceVersion": f"{feed}:{meta['lastModifiedDate']}:{meta['sha256']}",
        "sourcePublishedAt": meta["lastModifiedDate"],
        "observedAt": observed_at,
        "sourceSha256": sha256_file(source),
        "sourceBytes": source.stat().st_size,
        "nvdUncompressedSha256": meta["sha256"],
        "nvdUncompressedBytes": meta["size"],
    }


def epss_metadata(path):
    try:
        with gzip.open(path, "rt", encoding="utf-8", newline="") as handle:
            comments = []
            for _ in range(20):
                line = handle.readline()
                if not line:
                    break
                stripped = line.strip()
                if not stripped:
                    continue
                if stripped.startswith("#"):
                    comments.append(stripped[1:].strip())
                    continue
                if stripped == "cve,epss,percentile":
                    break
                raise RuntimeError("FIRST EPSS source has an unexpected header")
    except (OSError, UnicodeDecodeError) as exc:
        raise RuntimeError("FIRST EPSS source is not valid UTF-8 gzip CSV") from exc
    fields = {}
    for comment in comments:
        for part in comment.split(","):
            if ":" in part:
                key, value = part.split(":", 1)
            elif "=" in part:
                key, value = part.split("=", 1)
            else:
                continue
            fields[key.strip().lower()] = value.strip()
    model = fields.get("model_version", "")
    score_date = fields.get("score_date", "")
    if not EPSS_MODEL_RE.fullmatch(model):
        raise RuntimeError("FIRST EPSS model_version is missing or invalid")
    try:
        score_date = date.fromisoformat(score_date).isoformat()
    except ValueError as exc:
        raise RuntimeError("FIRST EPSS score_date is missing or invalid") from exc
    return model, score_date


def verify_bounded_gzip(path, maximum):
    size = 0
    try:
        with gzip.open(path, "rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > maximum:
                    raise RuntimeError("decompressed source exceeds configured maximum")
    except (OSError, EOFError) as exc:
        raise RuntimeError("source is not a valid complete gzip stream") from exc
    if size <= 0:
        raise RuntimeError("decompressed source is empty")
    return size


def acquire_epss(args, output, observed_at):
    source = output / "source.csv.gz"
    if args.offline_input:
        bounded_local_copy(args.offline_input, source, MAX_EPSS_COMPRESSED)
    else:
        fetch_bytes(
            FIRST_EPSS,
            source,
            MAX_EPSS_COMPRESSED,
            accept="application/gzip, application/octet-stream",
            allowed_hosts={"epss.empiricalsecurity.com"},
        )
    decompressed = verify_bounded_gzip(source, MAX_EPSS_UNCOMPRESSED)
    model, score_date = epss_metadata(source)
    return {
        "provider": "FIRST_EPSS",
        "syncMode": "BOOTSTRAP",
        "sourceFile": source.name,
        "sourceUri": FIRST_EPSS,
        "sourceVersion": f"{model}:{score_date}",
        "sourcePublishedAt": "",
        "observedAt": observed_at,
        "sourceSha256": sha256_file(source),
        "sourceBytes": source.stat().st_size,
        "decompressedBytes": decompressed,
        "modelVersion": model,
        "scoreDate": score_date,
    }


def acquire_cisa(args, output, observed_at):
    source = output / "source.json"
    if args.offline_input:
        bounded_local_copy(args.offline_input, source, MAX_CISA_BYTES)
    else:
        fetch_bytes(
            CISA_KEV,
            source,
            MAX_CISA_BYTES,
            accept="application/json",
            allowed_hosts={"www.cisa.gov"},
        )
    try:
        root = json.loads(source.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("CISA KEV source is not valid UTF-8 JSON") from exc
    if not isinstance(root, dict):
        raise RuntimeError("CISA KEV source root must be an object")
    catalog_version = str(root.get("catalogVersion") or "").strip()
    released = iso_timestamp(root.get("dateReleased"), "CISA dateReleased")
    count = root.get("count")
    vulns = root.get("vulnerabilities")
    if not catalog_version or isinstance(count, bool) or not isinstance(count, int) or count <= 0:
        raise RuntimeError("CISA KEV source metadata is incomplete")
    if not isinstance(vulns, list) or len(vulns) != count:
        raise RuntimeError("CISA KEV source declared count does not match parsed count")
    return {
        "provider": "CISA_KEV",
        "syncMode": "BOOTSTRAP",
        "sourceFile": source.name,
        "sourceUri": CISA_KEV,
        "sourceVersion": catalog_version,
        "sourcePublishedAt": released,
        "observedAt": observed_at,
        "sourceSha256": sha256_file(source),
        "sourceBytes": source.stat().st_size,
        "recordCount": count,
    }


def cve_commit_descriptor(payload):
    if not isinstance(payload, dict):
        raise RuntimeError("CVE Program commit descriptor must be an object")
    sha = str(payload.get("sha") or "").strip().lower()
    if not re.fullmatch(r"[a-f0-9]{40}", sha):
        raise RuntimeError("CVE Program main commit SHA is invalid")
    commit = payload.get("commit")
    if not isinstance(commit, dict):
        raise RuntimeError("CVE Program commit descriptor lacks commit metadata")
    committer = commit.get("committer")
    if not isinstance(committer, dict):
        raise RuntimeError("CVE Program commit descriptor lacks committer metadata")
    published = iso_timestamp(committer.get("date"), "CVE Program commit date")
    return sha, published


def read_json_descriptor(path, maximum, field):
    require_regular(path, field)
    if path.stat().st_size <= 0 or path.stat().st_size > maximum:
        raise RuntimeError(f"{field} is empty or too large")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"{field} must be UTF-8 JSON") from exc


def acquire_cve_program(args, output, observed_at):
    if args.offline_metadata:
        commit_payload = read_json_descriptor(
            args.offline_metadata, MAX_GITHUB_API_BYTES, "--offline-metadata"
        )
    else:
        commit_text = fetch_text(
            CVE_COMMIT_API,
            MAX_GITHUB_API_BYTES,
            allowed_hosts={"api.github.com"},
        )
        commit_payload = json.loads(commit_text)
    sha, published = cve_commit_descriptor(commit_payload)
    source_url = CVE_ARCHIVE.format(sha=sha)
    source = output / "source.zip"
    if args.offline_input:
        bounded_local_copy(args.offline_input, source, MAX_CVE_ARCHIVE_BYTES)
    else:
        fetch_bytes(
            source_url,
            source,
            MAX_CVE_ARCHIVE_BYTES,
            accept="application/zip, application/octet-stream",
            allowed_hosts={"github.com", "codeload.github.com"},
        )
    if not zipfile.is_zipfile(source):
        raise RuntimeError("CVE Program source is not a valid ZIP archive")
    with zipfile.ZipFile(source) as archive:
        cve_entries = [
            name for name in archive.namelist()
            if "/cves/" in name.replace("\\", "/") and name.lower().endswith(".json")
        ]
        if not cve_entries:
            raise RuntimeError("CVE Program archive contains no cves/*.json records")
    return {
        "provider": "CVE_PROGRAM",
        "syncMode": "BOOTSTRAP",
        "sourceFile": source.name,
        "sourceUri": source_url,
        "metadataUri": CVE_COMMIT_API,
        "sourceVersion": sha,
        "sourcePublishedAt": published,
        "observedAt": observed_at,
        "sourceSha256": sha256_file(source),
        "sourceBytes": source.stat().st_size,
        "archiveCveRecordCount": len(cve_entries),
    }


def main():
    args = arguments()
    observed_at = utc_now(args.observed_at)
    prepare_output(args.output)
    if args.provider != "NVD" and args.nvd_feed:
        raise RuntimeError("--nvd-feed is valid only for provider NVD")
    if args.provider != "NVD" and args.offline_metadata and args.provider != "CVE_PROGRAM":
        raise RuntimeError("--offline-metadata is valid only for NVD or CVE_PROGRAM")

    try:
        if args.provider == "NVD":
            descriptor = acquire_nvd(args, args.output, observed_at)
        elif args.provider == "FIRST_EPSS":
            descriptor = acquire_epss(args, args.output, observed_at)
        elif args.provider == "CISA_KEV":
            descriptor = acquire_cisa(args, args.output, observed_at)
        else:
            descriptor = acquire_cve_program(args, args.output, observed_at)
        descriptor["artifactType"] = "PUBLIC_INTELLIGENCE_SOURCE_ACQUISITION"
        descriptor["schemaVersion"] = 1
        descriptor["acquisitionMode"] = "OFFLINE_INPUT" if args.offline_input else "OFFICIAL_HTTPS"
        write_descriptor(args.output, descriptor)
    except Exception:
        for child in list(args.output.iterdir()):
            if child.is_file() and not child.is_symlink():
                child.unlink()
        raise

    print(
        f"public_intelligence_source=VALID provider={descriptor['provider']} "
        f"version={descriptor['sourceVersion']} sha256={descriptor['sourceSha256']} "
        f"output={args.output}"
    )


if __name__ == "__main__":
    main()
