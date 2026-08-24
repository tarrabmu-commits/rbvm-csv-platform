#!/usr/bin/env python3
"""Offline contract verification for PUBLIC_INTELLIGENCE_SYNC_BUNDLE_V1."""

import csv
import gzip
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
BUILDER = ROOT / "scripts" / "build-public-intelligence-sync-bundle.py"
EXPECTED_HEADER = [
    "CVE_ID",
    "Record_State",
    "Source_Modified_At",
    "Source_Published_At",
    "Observed_At",
    "Payload_Base64",
]


def run(*args):
    subprocess.run(
        [sys.executable, str(BUILDER), *map(str, args)],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def manifest(path):
    result = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        key, value = line.split("=", 1)
        result[key] = value
    return result


def records(path):
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.reader(handle, delimiter="\t")
        header = next(reader)
        assert header == EXPECTED_HEADER, header
        return list(reader)


def build(provider, source, output, source_uri, version, previous=None):
    arguments = [
        provider,
        source,
        output,
        "--mode",
        "BOOTSTRAP",
        "--source-uri",
        source_uri,
        "--source-version",
        version,
        "--observed-at",
        "2026-08-24T05:00:00Z",
    ]
    if previous:
        arguments += ["--previous-cves", previous]
    run(*arguments)
    meta = manifest(output / "manifest.properties")
    rows = records(output / "records.tsv")
    assert meta["artifactType"] == "PUBLIC_INTELLIGENCE_SYNC_BUNDLE"
    assert meta["schemaVersion"] == "1"
    assert meta["provider"] == provider
    assert meta["syncMode"] == "BOOTSTRAP"
    assert int(meta["recordCount"]) == len(rows)
    assert meta["recordsSha256"] == hashlib.sha256(
        (output / "records.tsv").read_bytes()
    ).hexdigest()
    assert len(meta["sourceSha256"]) == 64
    return rows


def main():
    assert BUILDER.is_file()
    with tempfile.TemporaryDirectory(prefix="rbvm-public-intel-bundle-") as temp:
        root = Path(temp)

        nvd = root / "nvd.json.gz"
        nvd.write_bytes(
            gzip.compress(
                json.dumps(
                    {
                        "vulnerabilities": [
                            {
                                "cve": {
                                    "id": "CVE-2026-10001",
                                    "published": "2026-08-20T00:00:00.000",
                                    "lastModified": "2026-08-23T12:00:00.000",
                                    "vulnStatus": "Analyzed",
                                }
                            }
                        ]
                    }
                ).encode("utf-8")
            )
        )
        nvd_rows = build(
            "NVD",
            nvd,
            root / "nvd-bundle",
            "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.gz",
            "modified-fixture",
        )
        assert nvd_rows[0][0:2] == ["CVE-2026-10001", "ACTIVE"]

        epss = root / "epss.csv.gz"
        epss.write_bytes(
            gzip.compress(
                (
                    "#model_version:v5,score_date:2026-08-24\n"
                    "cve,epss,percentile\n"
                    "CVE-2026-10001,0.420000,0.990000\n"
                ).encode("utf-8")
            )
        )
        previous = root / "previous.txt"
        previous.write_text(
            "CVE-2026-10001\nCVE-2026-10002\n", encoding="utf-8"
        )
        epss_rows = build(
            "FIRST_EPSS",
            epss,
            root / "epss-bundle",
            "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
            "v5-2026-08-24",
            previous,
        )
        assert [row[1] for row in epss_rows] == ["ACTIVE", "TOMBSTONE"]
        assert epss_rows[1][0] == "CVE-2026-10002"
        assert epss_rows[1][5] == ""

        cisa = root / "kev.json"
        cisa.write_text(
            json.dumps(
                {
                    "catalogVersion": "2026.08.24",
                    "count": 1,
                    "vulnerabilities": [
                        {
                            "cveID": "CVE-2026-10003",
                            "vendorProject": "Example",
                            "product": "Example",
                            "dateAdded": "2026-08-24",
                            "dueDate": "2026-09-14",
                            "knownRansomwareCampaignUse": "Unknown",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        cisa_rows = build(
            "CISA_KEV",
            cisa,
            root / "cisa-bundle",
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            "2026.08.24",
        )
        assert cisa_rows[0][0:2] == ["CVE-2026-10003", "ACTIVE"]

        cve_zip = root / "cvelist.zip"
        with zipfile.ZipFile(cve_zip, "w") as archive:
            archive.writestr(
                "cves/2026/10xxx/CVE-2026-10004.json",
                json.dumps(
                    {
                        "dataType": "CVE_RECORD",
                        "dataVersion": "5.1",
                        "cveMetadata": {
                            "cveId": "CVE-2026-10004",
                            "state": "PUBLISHED",
                            "datePublished": "2026-08-20T00:00:00.000Z",
                            "dateUpdated": "2026-08-23T00:00:00.000Z",
                        },
                        "containers": {"cna": {}},
                    }
                ),
            )
        cve_rows = build(
            "CVE_PROGRAM",
            cve_zip,
            root / "cve-bundle",
            "https://github.com/CVEProject/cvelistV5/releases/download/cve_fixture/cvelistV5.zip",
            "2026-08-24-midnight-fixture",
        )
        assert cve_rows[0][0:2] == ["CVE-2026-10004", "ACTIVE"]

        bad_cisa = root / "bad-kev.json"
        bad_cisa.write_text(
            json.dumps({"count": 2, "vulnerabilities": [{"cveID": "CVE-2026-10005"}]}),
            encoding="utf-8",
        )
        failed = subprocess.run(
            [
                sys.executable,
                str(BUILDER),
                "CISA_KEV",
                str(bad_cisa),
                str(root / "bad-bundle"),
                "--mode",
                "BOOTSTRAP",
                "--source-uri",
                "https://example.invalid/kev.json",
                "--source-version",
                "bad",
                "--observed-at",
                "2026-08-24T05:00:00Z",
            ],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        assert failed.returncode != 0

    print("Public intelligence sync bundle checks: PASS")


if __name__ == "__main__":
    main()
