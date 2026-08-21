#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CSS = ROOT / "src/main/resources/web/rbvm-ui.css"
JS = ROOT / "src/main/resources/web/rbvm-ui.js"


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise AssertionError(f"{path}: expected one exact navigation anchor, found {count}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


replace_once(
    JS,
    """  const pages = [
    ['/', 'Overview'],
    ['/cvss', 'CVSS'],
    ['/kev', 'KEV'],
    ['/epss', 'EPSS'],
    ['/asset-context', 'Asset Context'],
    ['/reachability', 'Reachability'],
    ['/business-impact', 'Business Impact'],
    ['/assets', 'Managed Assets'],
    ['/asset-links', 'Asset Links']
  ];""",
    """  const pages = [
    ['/', 'Home'],
    ['/cvss', 'CVSS'],
    ['/kev', 'KEV'],
    ['/epss', 'EPSS'],
    ['/asset-context', 'Context'],
    ['/reachability', 'Reachability'],
    ['/business-impact', 'Impact'],
    ['/assets', 'Assets'],
    ['/asset-links', 'Links']
  ];""",
)

replace_once(
    JS,
    """    nav.append(list);
    return nav;
  }

  function createShell() {""",
    """    nav.append(list);
    return nav;
  }

  function createMobileNav() {
    const disclosure = document.createElement('details');
    disclosure.className = 'rbvm-mobile-nav';

    const summary = document.createElement('summary');
    summary.textContent = 'التنقل';
    summary.setAttribute('aria-label', 'فتح قائمة التنقل');

    const nav = document.createElement('nav');
    nav.setAttribute('aria-label', 'التنقل الرئيسي للموبايل');
    const list = document.createElement('ul');
    const activePath = currentPath();

    for (const [href, label] of pages) {
      const item = document.createElement('li');
      const link = document.createElement('a');
      link.href = href;
      link.textContent = label;
      if (activePath === href) link.setAttribute('aria-current', 'page');
      item.append(link);
      list.append(item);
    }

    nav.append(list);
    disclosure.append(summary, nav);
    return disclosure;
  }

  function createShell() {""",
)

replace_once(
    JS,
    """    tools.append(themeButton);
    inner.append(brand, createNav(), tools);
    shell.append(inner);""",
    """    tools.append(themeButton);
    inner.append(brand, createNav(), createMobileNav(), tools);
    shell.append(inner);""",
)

replace_once(
    CSS,
    """.rbvm-nav {
  min-width: 0;
  overflow-x: auto;
  scrollbar-width: thin;
  padding-block: var(--rbvm-space-2);
}""",
    """.rbvm-nav {
  min-width: 0;
  overflow: hidden;
  padding-block: var(--rbvm-space-2);
}""",
)

replace_once(
    CSS,
    """.rbvm-nav a[aria-current=\"page\"] {
  background: color-mix(in srgb, var(--rbvm-accent) 13%, var(--rbvm-surface));
  border-color: color-mix(in srgb, var(--rbvm-accent) 48%, var(--rbvm-border));
  color: var(--rbvm-accent-strong) !important;
}
.rbvm-shell__tools""",
    """.rbvm-nav a[aria-current=\"page\"] {
  background: color-mix(in srgb, var(--rbvm-accent) 13%, var(--rbvm-surface));
  border-color: color-mix(in srgb, var(--rbvm-accent) 48%, var(--rbvm-border));
  color: var(--rbvm-accent-strong) !important;
}
.rbvm-mobile-nav { display: none; }
.rbvm-shell__tools""",
)

replace_once(
    CSS,
    """@media (max-width: 720px) {
  .rbvm-shell__inner, main, .rbvm-page-footer { width: min(100% - 20px, var(--rbvm-content-max)) !important; }
  main { padding-top: var(--rbvm-space-5) !important; }
  main > header:first-child { display: block; padding: var(--rbvm-space-5); }
  main > header:first-child > :last-child { margin-top: var(--rbvm-space-4); }
  .rbvm-brand__meta small { display: none; }
  .rbvm-nav a { min-height: var(--rbvm-control-min); }
  .panel { border-radius: var(--rbvm-radius-lg) !important; }
}""",
    """@media (max-width: 720px) {
  .rbvm-shell__inner, main, .rbvm-page-footer { width: min(100% - 20px, var(--rbvm-content-max)) !important; }
  main { padding-top: var(--rbvm-space-5) !important; }
  main > header:first-child { display: block; padding: var(--rbvm-space-5); }
  main > header:first-child > :last-child { margin-top: var(--rbvm-space-4); }
  .rbvm-brand__meta small { display: none; }
  .rbvm-nav { display: none; }
  .rbvm-mobile-nav {
    display: block;
    grid-column: 1 / -1;
    grid-row: 2;
    margin-bottom: .2rem;
  }
  .rbvm-mobile-nav summary {
    min-height: var(--rbvm-control-min);
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--rbvm-space-3);
    padding: .6rem .8rem;
    border: 1px solid var(--rbvm-border);
    border-radius: var(--rbvm-radius-md);
    background: var(--rbvm-surface);
    color: var(--rbvm-text);
    font-weight: 800;
    cursor: pointer;
    list-style: none;
  }
  .rbvm-mobile-nav summary::-webkit-details-marker { display: none; }
  .rbvm-mobile-nav summary::after { content: '＋'; color: var(--rbvm-accent-strong); }
  .rbvm-mobile-nav[open] summary::after { content: '−'; }
  .rbvm-mobile-nav nav { padding-top: var(--rbvm-space-2); }
  .rbvm-mobile-nav ul {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: var(--rbvm-space-2);
    list-style: none;
    margin: 0;
    padding: 0;
  }
  .rbvm-mobile-nav a {
    min-height: var(--rbvm-control-min);
    display: flex;
    align-items: center;
    justify-content: center;
    padding: .65rem .55rem;
    border: 1px solid var(--rbvm-border-soft);
    border-radius: var(--rbvm-radius-md);
    background: var(--rbvm-surface-2);
    color: var(--rbvm-text-muted) !important;
    font-size: .82rem;
    font-weight: 760;
    text-decoration: none;
    text-align: center;
  }
  .rbvm-mobile-nav a[aria-current=\"page\"] {
    border-color: color-mix(in srgb, var(--rbvm-accent) 50%, var(--rbvm-border));
    background: color-mix(in srgb, var(--rbvm-accent) 13%, var(--rbvm-surface));
    color: var(--rbvm-accent-strong) !important;
  }
  .panel { border-radius: var(--rbvm-radius-lg) !important; }
}""",
)

print("frontend navigation exact refinement: PASS")
