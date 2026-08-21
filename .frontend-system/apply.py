#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "src/main/resources/web"
CSS_LINK = '<link rel="stylesheet" href="/ui/rbvm-ui.css">'
JS_LINK = '<script src="/ui/rbvm-ui.js" defer></script>'
PAGES = (
    "index.html",
    "cvss-v31.html",
    "cisa-kev.html",
    "epss.html",
    "asset-context.html",
    "network-reachability.html",
    "business-impact.html",
    "assets.html",
    "asset-links.html",
)


def exact(path: Path, old: str, new: str, count: int = 1) -> None:
    value = path.read_text(encoding="utf-8")
    actual = value.count(old)
    if actual != count:
        raise AssertionError(f"{path}: expected {count} occurrence(s) of {old[:90]!r}, found {actual}")
    path.write_text(value.replace(old, new, count), encoding="utf-8")


def replace_all(path: Path, old: str, new: str, minimum: int = 1) -> int:
    value = path.read_text(encoding="utf-8")
    actual = value.count(old)
    if actual < minimum:
        raise AssertionError(f"{path}: expected at least {minimum} occurrence(s) of {old!r}, found {actual}")
    path.write_text(value.replace(old, new), encoding="utf-8")
    return actual


def patch_pages() -> None:
    for name in PAGES:
        path = WEB / name
        value = path.read_text(encoding="utf-8")
        if CSS_LINK in value or JS_LINK in value:
            raise AssertionError(f"{name}: shared frontend resource already present before applicator")
        if value.count("</head>") != 1 or value.count("</body>") != 1:
            raise AssertionError(f"{name}: expected one head/body closing tag")
        value = value.replace("</head>", f"  {CSS_LINK}\n</head>", 1)
        value = value.replace("</body>", f"{JS_LINK}\n</body>", 1)
        path.write_text(value, encoding="utf-8")


def patch_server() -> None:
    path = ROOT / "src/main/java/io/rbvm/csv/CsvPlatformServer.java"
    exact(
        path,
        "    private final byte[] scannerManagedAssetLinksUi;\n",
        "    private final byte[] scannerManagedAssetLinksUi;\n"
        "    private final byte[] frontendCss;\n"
        "    private final byte[] frontendJs;\n",
    )

    load_anchor = '        this.scannerManagedAssetLinksUi = loadResource("/web/asset-links.html");\n'
    value = path.read_text(encoding="utf-8")
    count = value.count(load_anchor)
    if count != 2:
        raise AssertionError(f"server UI load anchor count changed: expected 2, found {count}")
    value = value.replace(
        load_anchor,
        load_anchor
        + '        this.frontendCss = loadResource("/web/rbvm-ui.css");\n'
        + '        this.frontendJs = loadResource("/web/rbvm-ui.js");\n'
    )
    path.write_text(value, encoding="utf-8")

    route_anchor = '            if ("/".equals(path)) {\n'
    route_insert = (
        '            if ("/ui/rbvm-ui.css".equals(path)) {\n'
        '                requireMethod(exchange, method, "GET");\n'
        '                sendBytes(exchange, 200, "text/css; charset=utf-8", frontendCss);\n'
        '                return;\n'
        '            }\n'
        '            if ("/ui/rbvm-ui.js".equals(path)) {\n'
        '                requireMethod(exchange, method, "GET");\n'
        '                sendBytes(exchange, 200, "text/javascript; charset=utf-8", frontendJs);\n'
        '                return;\n'
        '            }\n'
    )
    exact(path, route_anchor, route_insert + route_anchor)

    old_csp = (
        '        headers.set("Content-Security-Policy",\n'
        '                "default-src \'self\'; style-src \'self\' \'unsafe-inline\'; script-src \'self\' \'unsafe-inline\'");\n'
    )
    new_csp = (
        '        headers.set("Content-Security-Policy",\n'
        '                "default-src \'self\'; style-src \'self\' \'unsafe-inline\'; "\n'
        '                        + "script-src \'self\' \'unsafe-inline\'; connect-src \'self\'; "\n'
        '                        + "img-src \'self\' data:; object-src \'none\'; base-uri \'none\'; "\n'
        '                        + "frame-ancestors \'none\'; form-action \'self\'");\n'
    )
    exact(path, old_csp, new_csp)


def patch_verify() -> None:
    path = ROOT / "scripts/verify.sh"
    anchor = 'python3 "$ROOT_DIR/scripts/verify-web.py"\n'
    exact(path, anchor, anchor + 'python3 "$ROOT_DIR/scripts/verify-frontend-system.py"\n')


def patch_version() -> None:
    exact(ROOT / "build.gradle.kts", 'version = "0.23.1-SNAPSHOT"', 'version = "0.23.2-SNAPSHOT"')
    exact(ROOT / "api/openapi.yaml", "  version: 0.23.1\n", "  version: 0.23.2\n")
    exact(ROOT / "scripts/build-distribution.sh", "VERSION=0.23.1", "VERSION=0.23.2")
    exact(ROOT / "scripts/verify-reproducible-build.sh", "VERSION=0.23.1", "VERSION=0.23.2")
    exact(
        ROOT / "scripts/verify-reproducible-build.sh",
        "Implementation-Version: 0.23.1",
        "Implementation-Version: 0.23.2",
    )
    exact(
        ROOT / "scripts/verify-api.py",
        'document.get("info", {}).get("version") != "0.23.1"',
        'document.get("info", {}).get("version") != "0.23.2"',
    )
    exact(
        ROOT / "scripts/verify-api.py",
        "OpenAPI info.version must match the pre-V24 hardening release 0.23.1",
        "OpenAPI info.version must match the frontend-system release 0.23.2",
    )
    exact(
        ROOT / "scripts/verify-scanner-managed-asset-link-api.py",
        "    'version: 0.23.1',\n",
        "    'version: 0.23.2',\n",
    )

    for workflow in (ROOT / ".github/workflows/verify.yml", ROOT / ".github/workflows/release.yml"):
        value = workflow.read_text(encoding="utf-8")
        count = value.count("0.23.1")
        if count < 1:
            raise AssertionError(f"{workflow}: no 0.23.1 release references found")
        workflow.write_text(value.replace("0.23.1", "0.23.2"), encoding="utf-8")

    readme = ROOT / "README.md"
    value = readme.read_text(encoding="utf-8")
    count = value.count("0.23.1")
    if count < 4:
        raise AssertionError(f"README: expected current 0.23.1 references, found {count}")
    value = value.replace("0.23.1", "0.23.2")
    bullet = "- Increment 23 يضيف `/asset-links` و`SCANNER_MANAGED_ASSET_LINK_API_V1` لعرض scanner assets وإدارة LINK/UNLINK/RELINK كسجل customer-confirmed append-only مع strong ETag/If-Match؛ لا توجد مطابقة تلقائية.\n"
    if value.count(bullet) != 1:
        raise AssertionError("README V23 link bullet anchor changed")
    frontend_bullet = (
        bullet
        + "- `RBVM_FRONTEND_SYSTEM_V1` يوحّد كل صفحات التشغيل ضمن shell/navigation وdesign tokens مشتركة، responsive RTL، focus واضح، reduced-motion/forced-colors، وجداول/forms/dialogs متناسقة من دون framework أوCDN خارجي.\n"
    )
    value = value.replace(bullet, frontend_bullet, 1)
    readme.write_text(value, encoding="utf-8")


def main() -> None:
    patch_pages()
    patch_server()
    patch_verify()
    patch_version()
    print("frontend-system exact applicator: PASS")


if __name__ == "__main__":
    main()
