(() => {
  'use strict';

  const FRONTEND_CONTRACT = 'RBVM_FRONTEND_SYSTEM_V1';
  const THEME_KEY = 'rbvm.ui.theme';
  const pages = [
    ['/', 'Home'],
    ['/cvss', 'CVSS'],
    ['/kev', 'KEV'],
    ['/epss', 'EPSS'],
    ['/asset-context', 'Context'],
    ['/reachability', 'Reachability'],
    ['/business-impact', 'Impact'],
    ['/assets', 'Assets'],
    ['/asset-links', 'Links']
  ];

  function currentPath() {
    const path = window.location.pathname || '/';
    return path.length > 1 ? path.replace(/\/+$/, '') : '/';
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

  function createNav() {
    const nav = document.createElement('nav');
    nav.className = 'rbvm-nav';
    nav.setAttribute('aria-label', 'التنقل الرئيسي');

    const list = document.createElement('ul');
    list.className = 'rbvm-nav__list';
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
    brand.innerHTML = '<span class="rbvm-brand__mark" aria-hidden="true">RB</span><span class="rbvm-brand__meta"><span>RBVM Platform</span><small>Evidence → Decision</small></span>';

    const tools = document.createElement('div');
    tools.className = 'rbvm-shell__tools';

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

    tools.append(themeButton);
    inner.append(brand, createNav(), createMobileNav(), tools);
    shell.append(inner);

    document.body.prepend(shell);
    document.body.prepend(skip);
    refreshThemeButton();
  }

  function normalizeMain() {
    const main = document.querySelector('main');
    if (!main) return;
    if (!main.id) main.id = 'rbvm-main';
    if (!main.hasAttribute('tabindex')) main.tabIndex = -1;
    const skip = document.querySelector('.rbvm-skip-link');
    if (skip) skip.href = `#${main.id}`;
  }

  function normalizeTables() {
    document.querySelectorAll('table').forEach((table, index) => {
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

  function normalizeDialogs() {
    document.querySelectorAll('dialog').forEach(dialog => {
      dialog.setAttribute('aria-modal', 'true');
      dialog.addEventListener('close', () => {
        const openerId = dialog.dataset.rbvmOpenerId;
        if (!openerId) return;
        const opener = document.getElementById(openerId);
        if (opener && typeof opener.focus === 'function') opener.focus();
        delete dialog.dataset.rbvmOpenerId;
      });
    });

    document.addEventListener('click', event => {
      const trigger = event.target.closest('button, a');
      if (!trigger || !trigger.id) return;
      queueMicrotask(() => {
        document.querySelectorAll('dialog[open]').forEach(dialog => {
          if (!dialog.dataset.rbvmOpenerId) dialog.dataset.rbvmOpenerId = trigger.id;
        });
      });
    }, true);
  }

  function createFooter() {
    if (document.querySelector('.rbvm-page-footer')) return;
    const footer = document.createElement('footer');
    footer.className = 'rbvm-page-footer';
    footer.innerHTML = '<span><strong>RBVM</strong> · Evidence-first decision platform</span><span>Frontend contract: <code>RBVM_FRONTEND_SYSTEM_V1</code></span>';
    document.body.append(footer);
  }

  function init() {
    applyTheme(readTheme());
    document.documentElement.dataset.rbvmFrontend = FRONTEND_CONTRACT;
    createShell();
    normalizeMain();
    normalizeTables();
    normalizeExternalState();
    normalizeDialogs();
    createFooter();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init, {once: true});
  } else {
    init();
  }
})();
