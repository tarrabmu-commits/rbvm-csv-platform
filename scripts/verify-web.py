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


def verify_page(path: Path, *, requires_session_token: bool) -> int:
    text = path.read_text(encoding="utf-8")
    parser = IdCollector()
    parser.feed(text)

    duplicates = sorted(
        identifier for identifier, count in Counter(parser.identifiers).items() if count > 1
    )
    if duplicates:
        raise AssertionError(f"{path.name} has duplicate identifiers: {duplicates}")

    identifiers = set(parser.identifiers)
    missing = sorted(set(re.findall(r"byId\('([^']+)'\)", text)) - identifiers)
    if missing:
        raise AssertionError(f"{path.name} JavaScript references missing HTML identifiers: {missing}")

    direct_protected = re.findall(
        r"fetch\((['\"`])/api/v1/(?!live|ready)([^'\"`]+)", text
    )
    if direct_protected:
        raise AssertionError(
            f"{path.name} protected API calls must use apiFetch so the bearer token is attached"
        )

    if requires_session_token and "sessionStorage.setItem('rbvmApiToken'" not in text:
        raise AssertionError(f"{path.name} must keep its API token scoped to the browser session")
    return len(identifiers)


def main():
    root = Path(__file__).resolve().parent.parent
    pages = [
        (root / "src/main/resources/web/index.html", True),
        (root / "src/main/resources/web/cvss-v31.html", True),
        (root / "src/main/resources/web/cisa-kev.html", True),
        (root / "src/main/resources/web/epss.html", True),
        (root / "src/main/resources/web/asset-context.html", True),
        (root / "src/main/resources/web/network-reachability.html", True),
    ]
    total_ids = sum(verify_page(path, requires_session_token=token) for path, token in pages)
    print(f"Web structural checks: PASS ({len(pages)} pages, {total_ids} unique page ids)")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(error, file=sys.stderr)
        raise
