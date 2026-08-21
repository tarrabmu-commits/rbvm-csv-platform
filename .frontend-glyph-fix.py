#!/usr/bin/env python3
from pathlib import Path

path = Path(__file__).resolve().parent / "src/main/resources/web/rbvm-ui.css"
text = path.read_text(encoding="utf-8")
for old, new in (("content: '＋';", "content: '+';"), ("content: '−';", "content: '-';")):
    if text.count(old) != 1:
        raise AssertionError(f"expected one mobile disclosure glyph anchor: {old}")
    text = text.replace(old, new, 1)
path.write_text(text, encoding="utf-8")
print("mobile disclosure glyph fix: PASS")
