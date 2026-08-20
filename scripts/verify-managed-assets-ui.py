#!/usr/bin/env python3
from collections import Counter
from html.parser import HTMLParser
from pathlib import Path
import re
import sys

class Collector(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.ids=[]
        self.tags=[]
    def handle_starttag(self, tag, attrs):
        values=dict(attrs)
        self.tags.append((tag,values))
        if 'id' in values:
            self.ids.append(values['id'])

def require(text, needle):
    if needle not in text:
        raise AssertionError(f'missing required UI invariant: {needle}')

def forbid(text, needle):
    if needle in text:
        raise AssertionError(f'forbidden UI construct: {needle}')

def main():
    path=Path(sys.argv[1] if len(sys.argv)>1 else '/mnt/data/assets.html')
    text=path.read_text(encoding='utf-8')
    parser=Collector(); parser.feed(text)
    duplicates=sorted(k for k,v in Counter(parser.ids).items() if v>1)
    if duplicates:
        raise AssertionError(f'duplicate ids: {duplicates}')
    missing=sorted(set(re.findall(r"byId\('([^']+)'\)",text))-set(parser.ids))
    if missing:
        raise AssertionError(f'JS references missing ids: {missing}')
    for needle in (
        '<html lang="ar" dir="rtl">',
        '<dialog id="createDialog"',
        '<dialog id="detailDialog"',
        '<dialog id="reviseDialog"',
        'role="status" aria-live="polite"',
        "sessionStorage.setItem('rbvmApiToken'",
        "apiFetch('/api/v1/health'",
        '/api/v1/managed-assets',
        "headers:{'Content-Type':'application/json','If-Match':selectedEtag}",
        "response.headers.get('ETag')",
        'if (response.status === 412)',
        'لا تعمل auto-merge',
        'customerAssetKey',
        'ASSET_CLASSIFICATION_GUIDE_V1',
        'MISSION_CRITICAL',
        'DISASTER_RECOVERY',
        'UNKNOWN',
        'CUSTOMER_DIRECT',
        'GUIDED',
        'nextAfterId',
        'nextBeforeRevision',
        'textContent',
    ):
        require(text,needle)
    for needle in (
        'innerHTML',
        "method:'DELETE'",
        'method:"DELETE"',
        'PATCH',
        'document.write',
    ):
        forbid(text,needle)
    # The only mention of localStorage is explanatory prose; forbid JS APIs specifically.
    if 'localStorage.' in text:
        raise AssertionError('must not use localStorage API')
    print(f'Managed assets UI checks: PASS ({len(parser.ids)} unique ids)')

if __name__=='__main__':
    main()
