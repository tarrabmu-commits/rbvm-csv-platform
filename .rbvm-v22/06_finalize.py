#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FILES = [
    'build.gradle.kts',
    'api/openapi.yaml',
    'scripts/build-distribution.sh',
    'scripts/verify-reproducible-build.sh',
    '.github/workflows/verify.yml',
    '.github/workflows/release.yml',
]

for relative in FILES:
    path = ROOT / relative
    text = path.read_text()
    if '0.22.0' in text and '0.21.0' not in text:
        continue
    if '0.21.0' not in text:
        raise SystemExit(f'{relative}: missing expected 0.21.0 release marker')
    path.write_text(text.replace('0.21.0', '0.22.0'))

print('V22 release version alignment: PASS')
