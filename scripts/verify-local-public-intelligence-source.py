#!/usr/bin/env python3
"""Offline verification for PUBLIC_INTELLIGENCE_SOURCE_ACQUISITION_V1."""

import gzip
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
FETCHER = ROOT / "scripts" / "fetch-local-public-intelligence-source.py"
OBSERVED = "2026-08-24T05:30:00Z"


def invoke(provider, output, source, metadata=None, *extra):
    args = [
        sys.executable,
        str(FETCHER),
        provider,
        str(output),
        "--observed-at",
        OBSERVED,
        "--offline-input",
        str(source),
    ]
    if metadata is not None:
        args += ["--offline-metadata", str(metadata)]
    args += list(extra)
    return subprocess.run(
        args,
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def require_success(completed):
    assert completed.returncode == 0, completed.stderr


def descriptor(output):
    value = json.loads((output / "acquisition.json").read_text(encoding="utf-8"))
    assert value["artifactType"] == "PUBLIC_INTELLIGENCE_SOURCE_ACQUISITION"
    assert value["schemaVersion"] == 1
    assert value["acquisitionMode"] == "OFFLINE_INPUT"
    assert value["observedAt"] == OBSERVED
    source = output / value["sourceFile"]
    assert source.is_file() and not source.is_symlink()
    assert value["sourceSha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
    return value


def main():
    source_text = FETCHER.read_text(encoding="utf-8")
    assert "Authorization" in source_text
    assert "if github_api_auth" in source_text
    assert 'hostname != "api.github.com"' in source_text
    assert "nvd.nist.gov" in source_text
    assert "epss.empiricalsecurity.com" in source_text
    assert "www.cisa.gov" in source_text
    assert "CVEProject/cvelistV5" in source_text

    with tempfile.TemporaryDirectory(prefix="rbvm-public-intel-source-") as temp:
        root = Path(temp)

        nvd_json = json.dumps(
            {
                "totalResults": 1,
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-2026-11001",
                            "published": "2026-08-20T00:00:00.000",
                            "lastModified": "2026-08-24T04:00:00.000",
                        }
                    }
                ],
            },
            separators=(",", ":"),
        ).encode("utf-8")
        nvd_gz = root / "nvd.json.gz"
        nvd_gz.write_bytes(gzip.compress(nvd_json))
        nvd_meta = root / "nvd.meta"
        nvd_meta.write_text(
            "lastModifiedDate:2026-08-24T01:00:00-04:00\n"
            f"size:{len(nvd_json)}\n"
            f"gzSize:{nvd_gz.stat().st_size}\n"
            f"sha256:{hashlib.sha256(nvd_json).hexdigest().upper()}\n",
            encoding="utf-8",
        )
        nvd_run = invoke(
            "NVD", root / "nvd-out", nvd_gz, nvd_meta, "--nvd-feed", "2026"
        )
        require_success(nvd_run)
        nvd_desc = descriptor(root / "nvd-out")
        assert nvd_desc["provider"] == "NVD"
        assert nvd_desc["syncMode"] == "BOOTSTRAP"
        assert nvd_desc["sourcePublishedAt"] == "2026-08-24T05:00:00Z"
        assert nvd_desc["nvdUncompressedSha256"] == hashlib.sha256(nvd_json).hexdigest()

        bad_meta = root / "bad.meta"
        bad_meta.write_text(
            "lastModifiedDate:2026-08-24T01:00:00-04:00\n"
            f"size:{len(nvd_json)}\n"
            f"gzSize:{nvd_gz.stat().st_size}\n"
            f"sha256:{'0' * 64}\n",
            encoding="utf-8",
        )
        bad_nvd = invoke(
            "NVD", root / "bad-nvd-out", nvd_gz, bad_meta, "--nvd-feed", "modified"
        )
        assert bad_nvd.returncode != 0
        assert not (root / "bad-nvd-out" / "acquisition.json").exists()

        epss = root / "epss.csv.gz"
        epss.write_bytes(
            gzip.compress(
                (
                    "#model_version:v2026.06.15,score_date:2026-08-24\n"
                    "cve,epss,percentile\n"
                    "CVE-2026-11001,0.25,0.80\n"
                ).encode("utf-8")
            )
        )
        epss_run = invoke("FIRST_EPSS", root / "epss-out", epss)
        require_success(epss_run)
        epss_desc = descriptor(root / "epss-out")
        assert epss_desc["provider"] == "FIRST_EPSS"
        assert epss_desc["sourceVersion"] == "v2026.06.15:2026-08-24"

        cisa = root / "kev.json"
        cisa.write_text(
            json.dumps(
                {
                    "title": "CISA Known Exploited Vulnerabilities Catalog",
                    "catalogVersion": "2026.08.24",
                    "dateReleased": "2026-08-24T04:00:00.000Z",
                    "count": 1,
                    "vulnerabilities": [
                        {
                            "cveID": "CVE-2026-11002",
                            "dateAdded": "2026-08-24",
                            "dueDate": "2026-09-14",
                            "knownRansomwareCampaignUse": "Unknown",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        cisa_run = invoke("CISA_KEV", root / "cisa-out", cisa)
        require_success(cisa_run)
        cisa_desc = descriptor(root / "cisa-out")
        assert cisa_desc["provider"] == "CISA_KEV"
        assert cisa_desc["recordCount"] == 1

        commit_sha = "1" * 40
        commit = root / "commit.json"
        commit.write_text(
            json.dumps(
                {
                    "sha": commit_sha,
                    "commit": {"committer": {"date": "2026-08-24T04:30:00Z"}},
                }
            ),
            encoding="utf-8",
        )
        archive = root / "cvelist.zip"
        with zipfile.ZipFile(archive, "w") as handle:
            handle.writestr("cvelistV5-main/deltaLog.json", "{}")
            handle.writestr(
                "cvelistV5-main/cves/2026/11xxx/CVE-2026-11003.json",
                json.dumps(
                    {
                        "dataType": "CVE_RECORD",
                        "dataVersion": "5.2",
                        "cveMetadata": {"cveId": "CVE-2026-11003"},
                        "containers": {"cna": {}},
                    }
                ),
            )
        cve_run = invoke("CVE_PROGRAM", root / "cve-out", archive, commit)
        require_success(cve_run)
        cve_desc = descriptor(root / "cve-out")
        assert cve_desc["provider"] == "CVE_PROGRAM"
        assert cve_desc["sourceVersion"] == commit_sha
        assert cve_desc["archiveCveRecordCount"] == 1
        assert cve_desc["sourceUri"].endswith(f"/{commit_sha}.zip")

    print("Local public intelligence source acquisition checks: PASS")


if __name__ == "__main__":
    main()
