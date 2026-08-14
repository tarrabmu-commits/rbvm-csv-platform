#!/usr/bin/env python3
from collections import Counter
from html.parser import HTMLParser
from pathlib import Path
import re
import sys


class IdCollector(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.identifiers = []

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if "id" in values:
            self.identifiers.append(values["id"])


def main():
    root = Path(__file__).resolve().parent.parent
    text = (root / "src/main/resources/web/index.html").read_text(encoding="utf-8")
    parser = IdCollector()
    parser.feed(text)

    duplicates = sorted(
        identifier for identifier, count in Counter(parser.identifiers).items() if count > 1
    )
    if duplicates:
        raise AssertionError(f"HTML has duplicate identifiers: {duplicates}")

    identifiers = set(parser.identifiers)
    missing = sorted(set(re.findall(r"byId\('([^']+)'\)", text)) - identifiers)
    if missing:
        raise AssertionError(f"JavaScript references missing HTML identifiers: {missing}")

    direct_protected = re.findall(
        r"fetch\((['\"`])/api/v1/(?!live|ready)([^'\"`]+)", text
    )
    if direct_protected:
        raise AssertionError("Protected API calls must use apiFetch so the bearer token is attached")

    if "sessionStorage.setItem('rbvmApiToken'" not in text:
        raise AssertionError("Web UI must keep its API token scoped to the browser session")

    print(f"Web structural checks: PASS ({len(identifiers)} unique ids)")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(error, file=sys.stderr)
        raise
