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
