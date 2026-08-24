#!/usr/bin/env python3
"""Run established CSV enrichment from a V30 local snapshot and harden report provenance."""

import argparse
import json
from pathlib import Path
import subprocess
import sys


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--intel-snapshot", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    return parser.parse_args()


def load_json(path, label):
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"{label} must be a regular file")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"{label} is not valid UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise RuntimeError(f"{label} must be a JSON object")
    return value


def write_json_atomic(path, value):
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    temporary.replace(path)


def main():
    args = arguments()
    if args.intel_snapshot.is_symlink() or not args.intel_snapshot.is_file():
        raise RuntimeError("local public-intelligence snapshot must be a regular file")

    # Do not deserialize the potentially large snapshot in this wrapper while the child
    # enricher is also holding it. The child performs full contract/SHA/scope validation;
    # local acquisition provenance is checked only after the child has exited, so the two
    # snapshot object graphs never coexist in separate Python processes.
    enricher = Path(__file__).resolve().with_name("enrich-uploaded-csv.py")
    command = [
        sys.executable,
        str(enricher),
        str(args.input),
        str(args.output),
        "--intel-snapshot", str(args.intel_snapshot),
        "--report", str(args.report),
    ]
    subprocess.run(command, check=True)

    snapshot = load_json(args.intel_snapshot, "local public-intelligence snapshot")
    acquisition = snapshot.get("acquisition")
    if not isinstance(acquisition, dict) or acquisition.get("mode") != "LOCAL_V30_STORE":
        args.output.unlink(missing_ok=True)
        args.report.unlink(missing_ok=True)
        raise RuntimeError("local CSV enrichment requires a LOCAL_V30_STORE snapshot")
    del snapshot

    report = load_json(args.report, "CSV-first enrichment report")
    report["acquisitionMode"] = "LOCAL_V30_STORE"
    report["databaseStateUsed"] = True
    report["databaseStateScope"] = "GLOBAL_PUBLIC_INTELLIGENCE_ONLY"
    report["tenantDatabaseStateUsed"] = False
    report["providerNetworkIoUsed"] = False
    write_json_atomic(args.report, report)
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
