#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FILES = [
    'build.gradle.kts',
    'api/openapi.yaml',
    'scripts/build-distribution.sh',
    'scripts/verify-reproducible-build.sh',
    'scripts/verify-api.py',
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

api_verifier = ROOT / 'scripts/verify-api.py'
api_text = api_verifier.read_text()
old_message = 'OpenAPI info.version must match Increment 21'
new_message = 'OpenAPI info.version must match Increment 22'
if old_message in api_text:
    api_text = api_text.replace(old_message, new_message)
elif new_message not in api_text:
    raise SystemExit('scripts/verify-api.py: missing expected Increment 21 verifier message')
api_verifier.write_text(api_text)

print('V22 release version alignment: PASS')
