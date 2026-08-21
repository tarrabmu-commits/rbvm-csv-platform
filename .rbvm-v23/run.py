#!/usr/bin/env python3
from pathlib import Path
import subprocess
import sys

script = Path(__file__).with_name("apply.py")
text = script.read_text(encoding="utf-8")
old = 'append_before(openapi, "components:\\n", scanner_paths)'
new = '''replace_exact(\n    openapi,\n    "components:\\n  securitySchemes:\\n",\n    scanner_paths + "components:\\n  securitySchemes:\\n",\n)'''
if text.count(old) != 1:
    raise AssertionError(f"expected one ambiguous OpenAPI marker, found {text.count(old)}")
script.write_text(text.replace(old, new), encoding="utf-8")
subprocess.run([sys.executable, str(script)], check=True)
