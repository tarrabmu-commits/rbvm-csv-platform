(() => {
  'use strict';

  const FRONTEND_CONTRACT = 'RBVM_FRONTEND_SYSTEM_V1';
  const THEME_KEY = 'rbvm.ui.theme';
  const dialogOpeners = new WeakMap();
  const PAGE_META = new Map([
    ['/', {id: 'overview', nav: 'Home', group: 'Platform', eyebrow: 'OPERATIONS · EVIDENCE → DECISION'}],
    ['/cvss', {id: 'cvss', nav: 'CVSS', group: 'Intelligence', eyebrow: 'TECHNICAL SEVERITY · CVSS v3.1'}],
    ['/kev', {id: 'kev', nav: 'KEV', group: 'Intelligence', eyebrow: 'KNOWN EXPLOITATION · CISA KEV'}],
    ['/epss', {id: 'epss', nav: 'EPSS', group: 'Intelligence', eyebrow: 'EXPLOITATION PROBABILITY · FIRST EPSS'}],
    ['/asset-context', {id: 'context', nav: 'Context', group: 'Context', eyebrow: 'ASSET CONTEXT · CUSTOMER EVIDENCE'}],
    ['/reachability', {id: 'reachability', nav: 'Reachability', group: 'Context', eyebrow: 'NETWORK REACHABILITY · SCOPED EVIDENCE'}],
    ['/business-impact', {id: 'impact', nav: 'Impact', group: 'Context', eyebrow: 'BUSINESS / MISSION IMPACT'}],
    ['/assets', {id: 'assets', nav: 'Assets', group: 'Assets', eyebrow: 'MANAGED ASSETS · CUSTOMER REGISTRY'}],
    ['/asset-links', {id: 'links', nav: 'Links', group: 'Assets', eyebrow: 'SCANNER ↔ MANAGED ASSET · EXPLICIT LINK'}]
  ]);
  const pages = Array.from(PAGE_META, ([href, meta]) => [href, meta.nav, meta.group]);

  function currentPath() {
    const path = window.location.pathname || '/';
    return path.length > 1 ? path.replace(/\/+$/, '') : '/';
  }

  function pageMeta() {
    return PAGE_META.get(currentPath()) || PAGE_META.get('/');
  }

  function readTheme() {
    try {
      const stored = window.localStorage.getItem(THEME_KEY);
      return stored === 'dark' || stored === 'light' ? stored : null;
    } catch (_) {
      return null;
    }
  }

  function storeTheme(theme) {
    try {
      if (theme) window.localStorage.setItem(THEME_KEY, theme);
      else window.localStorage.removeItem(THEME_KEY);
    } catch (_) {
      // UI preference storage is optional. The application must still function without it.
    }
  }

  function applyTheme(theme) {
    if (theme === 'dark' || theme === 'light') {
      document.documentElement.dataset.rbvmTheme = theme;
    } else {
      delete document.documentElement.dataset.rbvmTheme;
    }
  }

  function effectiveTheme() {
    const explicit = document.documentElement.dataset.rbvmTheme;
    if (explicit) return explicit;
    return window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
  }

  function markPageIdentity() {
    const meta = pageMeta();
    document.documentElement.dataset.rbvmPage = meta.id;
    document.documentElement.dataset.rbvmPageGroup = meta.group.toLowerCase();
  }

  function createNav() {
    const nav = document.createElement('nav');
    nav.className = 'rbvm-nav';
    nav.setAttribute('aria-label', 'التنقل الرئيسي');

    const list = document.createElement('ul');
    list.className = 'rbvm-nav__list';
    const activePath = currentPath();
    let previousGroup = null;

    for (const [href, label, group] of pages) {
      const item = document.createElement('li');
      item.dataset.rbvmNavGroup = group.toLowerCase();
      if (previousGroup && previousGroup !== group) item.classList.add('rbvm-nav__group-start');
      previousGroup = group;

      const link = document.createElement('a');
      link.href = href;
      link.textContent = label;
      link.dataset.rbvmNavGroup = group;
      if (activePath === href) link.setAttribute('aria-current', 'page');
      item.append(link);
      list.append(item);
    }

    nav.append(list);
    return nav;
  }

  function createMobileNav() {
    const disclosure = document.createElement('details');
    disclosure.className = 'rbvm-mobile-nav';

    const summary = document.createElement('summary');
    summary.textContent = 'التنقل';

    function refreshDisclosureLabel() {
      summary.setAttribute(
        'aria-label',
        disclosure.open ? 'إغلاق قائمة التنقل' : 'فتح قائمة التنقل'
      );
    }

    disclosure.addEventListener('toggle', refreshDisclosureLabel);
    refreshDisclosureLabel();

    const nav = document.createElement('nav');
    nav.setAttribute('aria-label', 'التنقل الرئيسي للموبايل');
    const list = document.createElement('ul');
    const activePath = currentPath();

    for (const [href, label, group] of pages) {
      const item = document.createElement('li');
      item.dataset.rbvmNavGroup = group.toLowerCase();
      const link = document.createElement('a');
      link.href = href;
      link.textContent = label;
      link.dataset.rbvmNavGroup = group;
      if (activePath === href) link.setAttribute('aria-current', 'page');
      item.append(link);
      list.append(item);
    }

    nav.append(list);
    disclosure.append(summary, nav);
    return disclosure;
  }

  function createShell() {
    if (document.querySelector('.rbvm-shell')) return;

    const skip = document.createElement('a');
    skip.className = 'rbvm-skip-link';
    skip.href = '#rbvm-main';
    skip.textContent = 'تجاوز إلى المحتوى الرئيسي';

    const shell = document.createElement('header');
    shell.className = 'rbvm-shell';
    shell.setAttribute('data-contract', FRONTEND_CONTRACT);

    const inner = document.createElement('div');
    inner.className = 'rbvm-shell__inner';

    const brand = document.createElement('a');
    brand.className = 'rbvm-brand';
    brand.href = '/';
    brand.setAttribute('aria-label', 'RBVM — الصفحة الرئيسية');
    brand.innerHTML = '<span class="rbvm-brand__mark" aria-hidden="true"><span>RB</span></span><span class="rbvm-brand__meta"><span>RBVM Platform</span><small><i aria-hidden="true"></i>Evidence → Decision</small></span>';

    const tools = document.createElement('div');
    tools.className = 'rbvm-shell__tools';

    const pageChip = document.createElement('span');
    pageChip.className = 'rbvm-shell__page-chip';
    pageChip.textContent = pageMeta().group;
    pageChip.setAttribute('aria-hidden', 'true');

    const themeButton = document.createElement('button');
    themeButton.className = 'rbvm-icon-button';
    themeButton.type = 'button';

    function refreshThemeButton() {
      const theme = effectiveTheme();
      const dark = theme === 'dark';
      themeButton.textContent = dark ? '☀' : '☾';
      themeButton.setAttribute('aria-pressed', dark ? 'true' : 'false');
      themeButton.setAttribute(
        'aria-label',
        dark ? 'التبديل إلى الوضع الفاتح' : 'التبديل إلى الوضع الداكن'
      );
      themeButton.setAttribute(
        'title',
        dark ? 'الوضع الفاتح' : 'الوضع الداكن'
      );
    }

    themeButton.addEventListener('click', () => {
      const next = effectiveTheme() === 'dark' ? 'light' : 'dark';
      applyTheme(next);
      storeTheme(next);
      refreshThemeButton();
    });

    if (window.matchMedia) {
      const systemTheme = window.matchMedia('(prefers-color-scheme: light)');
      if (typeof systemTheme.addEventListener === 'function') {
        systemTheme.addEventListener('change', () => {
          if (!document.documentElement.dataset.rbvmTheme) refreshThemeButton();
        });
      }
    }

    tools.append(pageChip, themeButton);
    inner.append(brand, createNav(), createMobileNav(), tools);
    shell.append(inner);

    document.body.prepend(shell);
    document.body.prepend(skip);
    refreshThemeButton();
  }

  function normalizeMain() {
    const main = document.querySelector('main');
    if (!main) return null;
    main.classList.add('rbvm-page');
    if (!main.id) main.id = 'rbvm-main';
    if (!main.hasAttribute('tabindex')) main.tabIndex = -1;
    const skip = document.querySelector('.rbvm-skip-link');
    if (skip) skip.href = `#${main.id}`;
    return main;
  }

  function enhanceHero(main) {
    if (!main) return;
    const hero = main.firstElementChild;
    if (!hero || hero.tagName !== 'HEADER') return;
    hero.classList.add('rbvm-page-hero');
    hero.dataset.rbvmModule = 'hero';

    const content = hero.querySelector(':scope > div:first-child') || hero;
    if (!content.querySelector('.rbvm-page-eyebrow')) {
      const eyebrow = document.createElement('div');
      eyebrow.className = 'rbvm-page-eyebrow';
      eyebrow.textContent = pageMeta().eyebrow;
      const heading = content.querySelector('h1');
      if (heading) content.insertBefore(eyebrow, heading);
      else content.prepend(eyebrow);
    }

    const contract = hero.querySelector('.badge, .pill, .tag, .chip');
    if (contract) contract.classList.add('rbvm-page-contract');
  }

  function normalizeModules(main) {
    if (!main) return;
    const modules = main.querySelectorAll('.panel');
    modules.forEach((module, index) => {
      module.classList.add('rbvm-module');
      module.dataset.rbvmModule = module.dataset.rbvmModule || 'section';
      module.style.setProperty('--rbvm-module-order', String(index));
    });

    main.querySelectorAll('.cards').forEach(collection => collection.classList.add('rbvm-metrics'));
    main.querySelectorAll('.card, .metric, .stat, .summary, .result-card').forEach(card => {
      card.classList.add('rbvm-metric-card');
    });
    main.querySelectorAll('.detail').forEach(card => card.classList.add('rbvm-detail-card'));
    main.querySelectorAll('.history-item').forEach(item => item.classList.add('rbvm-history-item'));
    main.querySelectorAll('.note').forEach(note => note.classList.add('rbvm-callout'));
    main.querySelectorAll('.scroll, .table-wrap, .table-scroll').forEach(frame => frame.classList.add('rbvm-table-frame'));
    main.querySelectorAll('.badge, .pill, .tag, .chip').forEach(chip => chip.classList.add('rbvm-chip'));
    main.querySelectorAll('.status, [role="status"]').forEach(status => status.classList.add('rbvm-status'));
  }

  function normalizeTables() {
    document.querySelectorAll('table').forEach((table, index) => {
      table.classList.add('rbvm-data-table');
      if (!table.querySelector('caption')) {
        const caption = document.createElement('caption');
        caption.className = 'sr-only';
        caption.textContent = `RBVM data table ${index + 1}`;
        table.prepend(caption);
      }
      table.querySelectorAll('thead th').forEach(th => {
        if (!th.hasAttribute('scope')) th.setAttribute('scope', 'col');
      });
    });
  }

  function normalizeExternalState() {
    document.querySelectorAll('[role="status"]').forEach(region => {
      if (!region.hasAttribute('aria-live')) region.setAttribute('aria-live', 'polite');
      if (!region.hasAttribute('aria-atomic')) region.setAttribute('aria-atomic', 'true');
    });
  }

  function normalizeSemanticStates() {
    const stateMap = new Map([
      ['PRESENT', 'present'],
      ['MISSING', 'missing'],
      ['UNKNOWN', 'unknown'],
      ['STALE', 'stale'],
      ['AMBIGUOUS', 'ambiguous'],
      ['ACTIVE', 'active'],
      ['RESOLVED', 'resolved'],
      ['LINKED', 'linked'],
      ['UNLINKED', 'unlinked']
    ]);
    const candidates = document.querySelectorAll('.badge, .pill, .tag, .chip, td');
    candidates.forEach(node => {
      const state = stateMap.get(node.textContent.trim().toUpperCase());
      if (state) node.dataset.rbvmState = state;
    });
    document.querySelectorAll('.status.error, [data-state="error"]').forEach(node => {
      node.dataset.rbvmState = 'error';
    });
    document.querySelectorAll('.status.success, [data-state="success"]').forEach(node => {
      node.dataset.rbvmState = 'success';
    });
  }

  function observeSemanticStates() {
    const main = document.querySelector('main');
    if (!main || typeof MutationObserver !== 'function') return;
    const observer = new MutationObserver(() => normalizeSemanticStates());
    observer.observe(main, {subtree: true, childList: true, characterData: true, attributes: true, attributeFilter: ['class', 'data-state']});
  }

  function normalizeDialogs() {
    document.querySelectorAll('dialog').forEach(dialog => {
      dialog.classList.add('rbvm-dialog');
      dialog.setAttribute('aria-modal', 'true');
      dialog.addEventListener('close', () => {
        const opener = dialogOpeners.get(dialog);
        if (opener && opener.isConnected && typeof opener.focus === 'function') opener.focus();
        dialogOpeners.delete(dialog);
      });
    });

    document.addEventListener('click', event => {
      if (!(event.target instanceof Element)) return;
      const trigger = event.target.closest('button, a');
      if (!trigger) return;
      queueMicrotask(() => {
        document.querySelectorAll('dialog[open]').forEach(dialog => {
          if (!dialogOpeners.has(dialog)) dialogOpeners.set(dialog, trigger);
        });
      });
    }, true);
  }

  function createFooter() {
    if (document.querySelector('.rbvm-page-footer')) return;
    const footer = document.createElement('footer');
    footer.className = 'rbvm-page-footer';
    footer.innerHTML = '<span><strong>RBVM</strong> · Evidence-first decision platform</span><span class="rbvm-page-footer__meta"><span>Modular operator UI</span><span aria-hidden="true">·</span><code>RBVM_FRONTEND_SYSTEM_V1</code></span>';
    document.body.append(footer);
  }

  function init() {
    applyTheme(readTheme());
    document.documentElement.dataset.rbvmFrontend = FRONTEND_CONTRACT;
    markPageIdentity();
    createShell();
    const main = normalizeMain();
    enhanceHero(main);
    normalizeModules(main);
    normalizeTables();
    normalizeExternalState();
    normalizeSemanticStates();
    observeSemanticStates();
    normalizeDialogs();
    createFooter();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init, {once: true});
  } else {
    init();
  }
})();
