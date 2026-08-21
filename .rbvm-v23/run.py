#!/usr/bin/env python3
from pathlib import Path
import subprocess
import sys

script = Path(__file__).with_name("apply.py")
text = script.read_text(encoding="utf-8")

old_marker = 'append_before(openapi, "components:\\n", scanner_paths)'
new_marker = '''replace_exact(\n    openapi,\n    "components:\\n  securitySchemes:\\n",\n    scanner_paths + "components:\\n  securitySchemes:\\n",\n)'''
if text.count(old_marker) != 1:
    raise AssertionError(f"expected one ambiguous OpenAPI marker, found {text.count(old_marker)}")
text = text.replace(old_marker, new_marker)

old_count = 'replace_exact("README.md", "rbvm-csv-platform-0.21.0.jar", "rbvm-csv-platform-0.23.0.jar", count=3)'
new_count = 'replace_exact("README.md", "rbvm-csv-platform-0.21.0.jar", "rbvm-csv-platform-0.23.0.jar", count=2)'
if text.count(old_count) != 1:
    raise AssertionError(f"expected one README JAR count guard, found {text.count(old_count)}")
text = text.replace(old_count, new_count)

script.write_text(text, encoding="utf-8")
subprocess.run([sys.executable, str(script)], check=True)
