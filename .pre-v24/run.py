#!/usr/bin/env python3
from pathlib import Path
import subprocess
import sys

script = Path(__file__).with_name("apply.py")
text = script.read_text(encoding="utf-8")
old = '''    if text.count('type="number" min="1"') != 2:\n        raise AssertionError("guideRevision numeric anchors changed")\n    text = text.replace('type="number" min="1"', 'type="number" min="1" step="1"')\n'''
new = '''    create_revision = 'type="number" min="1" value="1"'\n    revise_revision = 'type="number" min="1">'\n    if text.count(create_revision) != 1 or text.count(revise_revision) != 1:\n        raise AssertionError("guideRevision numeric anchors changed")\n    text = text.replace(create_revision, 'type="number" min="1" step="1" value="1"', 1)\n    text = text.replace(revise_revision, 'type="number" min="1" step="1">', 1)\n'''
if text.count(old) != 1:
    raise AssertionError(f"expected one guideRevision guard block, found {text.count(old)}")
script.write_text(text.replace(old, new, 1), encoding="utf-8")
subprocess.run([sys.executable, str(script)], check=True)

verifier = script.parents[1] / "scripts/verify-scanner-managed-asset-link-api.py"
verifier_text = verifier.read_text(encoding="utf-8")
old_version = "    'version: 0.23.0',\n"
new_version = "    'version: 0.23.1',\n"
if verifier_text.count(old_version) != 1:
    raise AssertionError(
        f"expected one V23 API release-version verifier anchor, found {verifier_text.count(old_version)}"
    )
verifier.write_text(verifier_text.replace(old_version, new_version, 1), encoding="utf-8")

build_file = script.parents[1] / "build.gradle.kts"
build_text = build_file.read_text(encoding="utf-8")
old_toolchain = "languageVersion.set(JavaLanguageVersion.of(25))"
new_toolchain = "languageVersion.set(JavaLanguageVersion.of(17))"
if build_text.count(old_toolchain) != 1:
    raise AssertionError(f"expected one Java 25 toolchain drift anchor, found {build_text.count(old_toolchain)}")
build_file.write_text(build_text.replace(old_toolchain, new_toolchain, 1), encoding="utf-8")

hardening_doc = script.parents[1] / "docs/PRE_V24_HARDENING.md"
doc_text = hardening_doc.read_text(encoding="utf-8")
old_pg = "PostgreSQL CI uses a digest-pinned PostgreSQL 16.12 image"
new_pg = "PostgreSQL CI uses a digest-pinned PostgreSQL 16.14 image"
if doc_text.count(old_pg) != 1:
    raise AssertionError(f"expected one PostgreSQL hardening-doc version anchor, found {doc_text.count(old_pg)}")
doc_text = doc_text.replace(old_pg, new_pg, 1)
doc_text += "\nThe Gradle Java toolchain now targets Java 17, matching the compiler `--release 17` and documented runtime floor.\n"
hardening_doc.write_text(doc_text, encoding="utf-8")
