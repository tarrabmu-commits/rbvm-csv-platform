(() => {
  'use strict';

  const FRONTEND_CONTRACT = 'RBVM_FRONTEND_SYSTEM_V1';
  const THEME_KEY = 'rbvm.ui.theme';
  const TOKEN_KEY = 'rbvmApiToken';
  const dialogOpeners = new WeakMap();
  const PAGE_META = new Map([
    ['/', {id: 'overview', nav: 'العمليات', group: 'المنصة', eyebrow: 'مركز عمليات المخاطر', title: 'المخاطر، بقرار واضح', description: 'حوّل أدلة الثغرات إلى قرارات قابلة للتتبع، من الاستيراد حتى المعالجة.'}],
    ['/cvss', {id: 'cvss', nav: 'الشدة', group: 'معلومات الثغرات', eyebrow: 'الشدة التقنية · CVSS v3.1', title: 'الشدة التقنية', description: 'سجل درجات CVSS ومصادرها كما وردت، من دون خلطها بالأولوية أو أثر الأعمال.'}],
    ['/kev', {id: 'kev', nav: 'الاستغلال', group: 'معلومات الثغرات', eyebrow: 'الاستغلال المعروف · CISA KEV', title: 'الثغرات المستغلة', description: 'تابع أدلة الاستغلال المعروفة وتاريخ رصدها بمصدر واضح وقابل للمراجعة.'}],
    ['/epss', {id: 'epss', nav: 'الاحتمالية', group: 'معلومات الثغرات', eyebrow: 'احتمالية الاستغلال · FIRST EPSS', title: 'احتمالية الاستغلال', description: 'اعرض احتمال الاستغلال وترتيبه المئوي كدليل مستقل مرتبط بلقطة زمنية.'}],
    ['/asset-context', {id: 'context', nav: 'السياق', group: 'سياق القرار', eyebrow: 'سياق الأصل · دليل المؤسسة', title: 'سياق الأصول', description: 'وثّق المالك والخدمة والبيئة والأهمية التشغيلية من المصدر المسؤول.'}],
    ['/reachability', {id: 'reachability', nav: 'الوصول', group: 'سياق القرار', eyebrow: 'قابلية الوصول · دليل محدد النطاق', title: 'قابلية الوصول الشبكي', description: 'سجل ما يمكن الوصول إليه، من أين، وفي أي وقت من دون استنتاجات مخفية.'}],
    ['/business-impact', {id: 'impact', nav: 'الأثر', group: 'سياق القرار', eyebrow: 'الأثر التشغيلي والمهماتي', title: 'الأثر التشغيلي', description: 'اربط الثغرات بتأثيرها الفعلي على الخدمة والعمل بلغة نوعية مفهومة.'}],
    ['/assets', {id: 'assets', nav: 'الأصول', group: 'إدارة الأصول', eyebrow: 'سجل الأصول المُدارة', title: 'الأصول المُدارة', description: 'سجل موحد للأصول التي تملكها المؤسسة مع تاريخ كامل لكل تعديل.'}],
    ['/asset-links', {id: 'links', nav: 'الربط', group: 'إدارة الأصول', eyebrow: 'ربط الماسح بالأصل المُدار', title: 'ربط أصول الماسح', description: 'اعتمد الربط أو فكه بقرار صريح يحفظ التاريخ ولا يعتمد على تخمين تلقائي.'}]
  ]);
  const pages = Array.from(PAGE_META, ([href, meta]) => [href, meta.nav, meta.group]);

  function currentPath() {
    const path = window.location.pathname || '/';
    return path.length > 1 ? path.replace(/\/+$/, '') : '/';
  }

  function pageMeta() {
    return PAGE_META.get(currentPath()) || PAGE_META.get('/');
  }

  function icon(name) {
    const paths = {
      sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.42 1.42M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.42-1.42M17.66 6.34l1.41-1.41"/>',
      moon: '<path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z"/>',
      login: '<path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4M10 17l5-5-5-5M15 12H3"/>',
      logout: '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/>',
      shield: '<path d="M20 13c0 5-3.5 7.5-8 9-4.5-1.5-8-4-8-9V5l8-3 8 3v8Z"/><path d="m9 12 2 2 4-4"/>',
      eye: '<path d="M2.1 12a10.7 10.7 0 0 1 19.8 0 10.7 10.7 0 0 1-19.8 0Z"/><circle cx="12" cy="12" r="3"/>',
      close: '<path d="M18 6 6 18M6 6l12 12"/>'
    };
    return `<svg class="rbvm-icon" aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${paths[name] || ''}</svg>`;
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
    return 'light';
  }

  function markPageIdentity() {
    const meta = pageMeta();
    document.documentElement.dataset.rbvmPage = meta.id;
    document.documentElement.dataset.rbvmPageGroup = meta.group.toLowerCase();
  }

  function containGeneratedNav(nav) {
    nav.style.setProperty('display', 'block', 'important');
    nav.style.setProperty('gap', '0', 'important');
    nav.style.setProperty('flex-wrap', 'nowrap', 'important');
  }

  function createNav() {
    const nav = document.createElement('nav');
    nav.className = 'rbvm-nav';
    nav.setAttribute('aria-label', 'التنقل الرئيسي');
    containGeneratedNav(nav);

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
    containGeneratedNav(nav);
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

  function readSessionToken() {
    try {
      return window.sessionStorage.getItem(TOKEN_KEY) || '';
    } catch (_) {
      return '';
    }
  }

  function storeSessionToken(token) {
    try {
      if (token) window.sessionStorage.setItem(TOKEN_KEY, token);
      else window.sessionStorage.removeItem(TOKEN_KEY);
    } catch (_) {
      // Storage can be unavailable in hardened browser modes; validation still works once.
    }
  }

  async function validateSession(token) {
    const response = await fetch('/api/v1/session', {
      cache: 'no-store',
      headers: {'Authorization': `Bearer ${token}`}
    });
    if (!response.ok) {
      const problem = await response.json().catch(() => ({}));
      const error = new Error(problem.detail || (response.status === 401 ? 'رمز الدخول غير صحيح.' : `تعذر تسجيل الدخول (${response.status}).`));
      error.status = response.status;
      throw error;
    }
    return response.json();
  }

  function createSessionControl() {
    const trigger = document.createElement('button');
    trigger.className = 'rbvm-session-button';
    trigger.type = 'button';
    trigger.setAttribute('aria-label', 'تسجيل الدخول إلى المنصة');
    trigger.setAttribute('title', 'تسجيل الدخول');
    trigger.innerHTML = `${icon('login')}<span class="rbvm-session-button__copy"><strong>تسجيل الدخول</strong><small>جلسة آمنة</small></span>`;

    const dialog = document.createElement('dialog');
    dialog.className = 'rbvm-session-dialog rbvm-dialog';
    dialog.setAttribute('aria-labelledby', 'rbvm-session-title');
    dialog.innerHTML = `
      <div class="rbvm-session-dialog__head">
        <span class="rbvm-session-dialog__symbol">${icon('shield')}</span>
        <div><p>هوية المشغّل</p><h2 id="rbvm-session-title">الدخول إلى المنصة</h2></div>
        <button class="rbvm-icon-button rbvm-session-close" type="button" aria-label="إغلاق" title="إغلاق">${icon('close')}</button>
      </div>
      <div class="rbvm-session-current" hidden>
        <div><span>المستخدم الحالي</span><strong data-session-actor></strong></div>
        <span class="rbvm-role" data-session-role></span>
      </div>
      <form class="rbvm-session-form">
        <p>أدخل رمز الوصول الذي زوّدك به مسؤول المنصة. يبقى الرمز في هذا التبويب فقط ويُحذف عند إغلاقه.</p>
        <label for="rbvm-session-token">رمز الوصول</label>
        <div class="rbvm-secret-field">
          <input id="rbvm-session-token" type="password" autocomplete="off" spellcheck="false" required placeholder="ألصق رمز الوصول">
          <button type="button" class="rbvm-icon-button rbvm-secret-toggle" aria-label="إظهار الرمز" title="إظهار الرمز">${icon('eye')}</button>
        </div>
        <div class="rbvm-session-feedback" role="status" aria-live="polite"></div>
        <div class="rbvm-session-actions">
          <button type="submit">دخول</button>
          <button type="button" class="ghost rbvm-session-cancel">إلغاء</button>
          <button type="button" class="danger rbvm-session-logout" hidden>${icon('logout')}<span>إنهاء الجلسة</span></button>
        </div>
      </form>`;
    document.body.append(dialog);

    const form = dialog.querySelector('.rbvm-session-form');
    const input = dialog.querySelector('#rbvm-session-token');
    const feedback = dialog.querySelector('.rbvm-session-feedback');
    const submit = form.querySelector('button[type="submit"]');
    const current = dialog.querySelector('.rbvm-session-current');
    const logout = dialog.querySelector('.rbvm-session-logout');

    function setIdentity(identity) {
      const roleLabels = {VIEWER: 'مشاهد', OPERATOR: 'مشغّل', ADMIN: 'مسؤول'};
      document.body.dataset.rbvmAuth = 'authenticated';
      trigger.classList.add('is-authenticated');
      trigger.setAttribute('aria-label', `الجلسة الحالية: ${identity.actorId}`);
      trigger.setAttribute('title', 'إدارة الجلسة');
      trigger.innerHTML = `${icon('shield')}<span class="rbvm-session-button__copy"><strong></strong><small></small></span>`;
      trigger.querySelector('strong').textContent = roleLabels[identity.role] || identity.role;
      trigger.querySelector('small').textContent = identity.actorId;
      current.hidden = false;
      current.querySelector('[data-session-actor]').textContent = identity.actorId;
      current.querySelector('[data-session-role]').textContent = roleLabels[identity.role] || identity.role;
      logout.hidden = false;
      submit.hidden = true;
      input.closest('.rbvm-secret-field').hidden = true;
      dialog.querySelector('label[for="rbvm-session-token"]').hidden = true;
      form.querySelector('p').textContent = 'الجلسة فعّالة في هذا التبويب. يمكنك إنهاؤها فوراً من هنا.';
    }

    async function refreshIdentity() {
      const token = readSessionToken();
      if (!token) {
        document.body.dataset.rbvmAuth = 'anonymous';
        return;
      }
      trigger.classList.add('is-loading');
      try {
        setIdentity(await validateSession(token));
      } catch (_) {
        storeSessionToken('');
        document.body.dataset.rbvmAuth = 'anonymous';
      } finally {
        trigger.classList.remove('is-loading');
      }
    }

    trigger.addEventListener('click', () => {
      dialog.showModal();
      if (!readSessionToken()) requestAnimationFrame(() => input.focus());
    });
    dialog.querySelector('.rbvm-session-close').addEventListener('click', () => dialog.close());
    dialog.querySelector('.rbvm-session-cancel').addEventListener('click', () => dialog.close());
    dialog.querySelector('.rbvm-secret-toggle').addEventListener('click', event => {
      const visible = input.type === 'text';
      input.type = visible ? 'password' : 'text';
      event.currentTarget.setAttribute('aria-label', visible ? 'إظهار الرمز' : 'إخفاء الرمز');
      event.currentTarget.setAttribute('title', visible ? 'إظهار الرمز' : 'إخفاء الرمز');
    });
    form.addEventListener('submit', async event => {
      event.preventDefault();
      const token = input.value.trim();
      if (!token) return;
      submit.disabled = true;
      feedback.className = 'rbvm-session-feedback';
      feedback.textContent = 'جارٍ التحقق من الهوية…';
      try {
        const identity = await validateSession(token);
        storeSessionToken(token);
        feedback.classList.add('success');
        feedback.textContent = `مرحباً ${identity.actorId}. جارٍ تجهيز مساحة العمل…`;
        window.setTimeout(() => window.location.reload(), 350);
      } catch (error) {
        feedback.classList.add('error');
        feedback.textContent = error.message || 'تعذر التحقق من رمز الدخول.';
        input.select();
      } finally {
        submit.disabled = false;
      }
    });
    logout.addEventListener('click', () => {
      storeSessionToken('');
      window.location.reload();
    });
    refreshIdentity();
    if (new URLSearchParams(window.location.search).get('login') === '1') {
      window.setTimeout(() => {
        dialog.showModal();
        input.focus();
      }, 0);
    }
    return trigger;
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
    // Legacy pages predate the shared shell and contain broad `header` rules.
    // Contain those rules here so the global application chrome stays full-width and predictable.
    shell.style.setProperty('display', 'block', 'important');
    shell.style.setProperty('width', '100%', 'important');
    shell.style.setProperty('max-width', 'none', 'important');
    shell.style.setProperty('margin', '0', 'important');
    shell.style.setProperty('padding', '0', 'important');
    shell.style.setProperty('gap', '0', 'important');

    const inner = document.createElement('div');
    inner.className = 'rbvm-shell__inner';

    const brand = document.createElement('a');
    brand.className = 'rbvm-brand';
    brand.href = '/';
    brand.setAttribute('aria-label', 'منصة RBVM — الصفحة الرئيسية');
    brand.innerHTML = '<span class="rbvm-brand__mark" aria-hidden="true"><span>R</span></span><span class="rbvm-brand__meta"><span>منصة RBVM</span><small><i aria-hidden="true"></i>قرار مبني على الدليل</small></span>';

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
      themeButton.innerHTML = icon(dark ? 'sun' : 'moon');
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

    const primaryNav = createNav();
    const mobileNav = createMobileNav();
    tools.append(pageChip, themeButton, createSessionControl());
    inner.append(brand, primaryNav, mobileNav, tools);
    shell.append(inner);

    const compactNavigation = window.matchMedia('(max-width: 960px)');
    function syncPrimaryNavigation() {
      primaryNav.style.setProperty('display', compactNavigation.matches ? 'none' : 'block', 'important');
    }
    if (typeof compactNavigation.addEventListener === 'function') {
      compactNavigation.addEventListener('change', syncPrimaryNavigation);
    }
    syncPrimaryNavigation();

    document.body.prepend(shell);
    document.body.prepend(skip);
    refreshThemeButton();
  }

  function normalizeMain() {
    const main = document.querySelector('main');
    if (!main) return null;
    main.classList.add('rbvm-page');
    main.style.setProperty('max-width', 'none', 'important');
    if (!main.id) main.id = 'rbvm-main';
    if (!main.hasAttribute('tabindex')) main.tabIndex = -1;
    const skip = document.querySelector('.rbvm-skip-link');
    if (skip) skip.href = `#${main.id}`;
    return main;
  }

  function normalizeLegacyHero(main) {
    if (!main || (main.firstElementChild && main.firstElementChild.tagName === 'HEADER')) return;
    const legacyHeader = main.previousElementSibling;
    if (!legacyHeader || legacyHeader.tagName !== 'HEADER' || legacyHeader.classList.contains('rbvm-shell')) return;
    main.prepend(legacyHeader);
  }

  function enhanceHero(main) {
    if (!main) return;
    const hero = main.firstElementChild;
    if (!hero || hero.tagName !== 'HEADER') return;
    hero.classList.add('rbvm-page-hero');
    hero.dataset.rbvmModule = 'hero';

    const content = hero.querySelector(':scope > div:first-child') || hero;
    const meta = pageMeta();
    const heading = content.querySelector('h1');
    if (heading) heading.textContent = meta.title;
    const description = heading && heading.nextElementSibling;
    if (description && description.tagName === 'P') description.textContent = meta.description;
    if (!content.querySelector('.rbvm-page-eyebrow')) {
      const eyebrow = document.createElement('div');
      eyebrow.className = 'rbvm-page-eyebrow';
      eyebrow.textContent = meta.eyebrow;
      if (heading) content.insertBefore(eyebrow, heading);
      else content.prepend(eyebrow);
    }

    const contract = hero.querySelector('.badge, .pill, .tag, .chip');
    if (contract) {
      contract.classList.add('rbvm-page-contract');
      if (meta.id === 'overview') contract.textContent = 'أدلة CSV · نتائج موحّدة · قابلية التطبيق';
    }
    const localNav = hero.querySelector(':scope > nav');
    if (localNav) localNav.classList.add('rbvm-page-links');
  }

  function normalizeModules(main) {
    if (!main) return;
    const modules = main.querySelectorAll('.panel');
    modules.forEach((module, index) => {
      module.classList.add('rbvm-module');
      module.dataset.rbvmModule = module.dataset.rbvmModule || 'section';
      module.style.setProperty('--rbvm-module-order', String(index));
    });

    document.querySelectorAll('.cards').forEach(collection => collection.classList.add('rbvm-metrics'));
    document.querySelectorAll('.card, .metric, .stat, .summary, .result-card').forEach(card => {
      card.classList.add('rbvm-metric-card');
    });
    document.querySelectorAll('.detail').forEach(card => card.classList.add('rbvm-detail-card'));
    document.querySelectorAll('.history-item').forEach(item => item.classList.add('rbvm-history-item'));
    document.querySelectorAll('.note').forEach(note => note.classList.add('rbvm-callout'));
    document.querySelectorAll('.scroll, .table-wrap, .table-scroll').forEach(frame => frame.classList.add('rbvm-table-frame'));
    document.querySelectorAll('.badge, .pill, .tag, .chip, .status-pill').forEach(chip => chip.classList.add('rbvm-chip'));
    document.querySelectorAll('.status, [role="status"]').forEach(status => status.classList.add('rbvm-status'));
  }

  function localizeInterface() {
    const translations = new Map([
      ['1. ارفع ملف Wazuh وحلّله', 'استيراد ملف Wazuh'],
      ['2. نتيجة المعاينة', 'نتيجة المعاينة'],
      ['3. Applicability Assessment', 'تقييم قابلية التطبيق'],
      ['4. الكاتالوج الموحّد', 'سجل النتائج الموحّد'],
      ['5. تفاصيل الحالة', 'تفاصيل الحالة'],
      ['2. Current CISA KEV Evidence', 'أدلة الاستغلال الحالية'],
      ['2. Current CVSS v3.1 Evidence', 'أدلة الشدة الحالية'],
      ['2. Current EPSS Evidence', 'أدلة احتمالية الاستغلال الحالية'],
      ['2. Current Per-Source Asset Context', 'سياق الأصول الحالي حسب المصدر'],
      ['2. Current Scoped Reachability Evidence', 'أدلة قابلية الوصول الحالية'],
      ['Current evidence per source + service + dimension', 'الأدلة الحالية حسب المصدر والخدمة ونوع الأثر'],
      ['Current Managed Assets', 'الأصول المُدارة الحالية'],
      ['Managed Asset Details', 'تفاصيل الأصل المُدار'],
      ['Audit Trail', 'سجل التدقيق'],
      ['Exposures', 'مواضع التعرّض'],
      ['Business Criticality', 'الأهمية التشغيلية'],
      ['Business Owner', 'مالك العمل'],
      ['Business Service', 'خدمة العمل'],
      ['Environment', 'البيئة'],
      ['Lifecycle', 'دورة الحياة'],
      ['Limit', 'عدد النتائج'],
      ['After ID', 'المعرّف التالي'],
      ['Source Profile ID', 'معرّف ملف المصدر'],
      ['CSV Contract', 'عقد CSV'],
      ['Choose File', 'اختيار ملف'],
      ['No file chosen', 'لم يُختر ملف'],
      ['Refresh', 'تحديث'],
      ['Create Managed Asset', 'إنشاء أصل مُدار'],
      ['Add Managed Asset Revision', 'إضافة نسخة جديدة للأصل']
    ]);
    document.querySelectorAll('h2, h3, button, th, label, option').forEach(element => {
      element.childNodes.forEach(node => {
        if (node.nodeType !== Node.TEXT_NODE) return;
        const original = node.nodeValue;
        const key = original.trim();
        if (!translations.has(key)) return;
        node.nodeValue = original.replace(key, translations.get(key));
      });
    });
  }

  function normalizeAuthMessages() {
    if (document.body.dataset.rbvmAuth !== 'anonymous') return;
    const runtime = document.querySelector('#runtimeHealth');
    if (runtime && runtime.textContent !== 'سجّل الدخول لعرض حالة المنصة والبيانات.') {
      runtime.textContent = 'سجّل الدخول لعرض حالة المنصة والبيانات.';
      runtime.classList.remove('degraded');
    }
  }

  function normalizeLegacyAuth() {
    document.querySelectorAll('#apiToken').forEach(input => {
      const section = input.closest('section, .panel');
      if (section) {
        section.classList.add('rbvm-legacy-auth');
        section.setAttribute('aria-hidden', 'true');
      }
    });
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

  function normalizeGuideTabs() {
    document.querySelectorAll('.guide-tab').forEach(tab => {
      const active = tab.classList.contains('active');
      tab.classList.toggle('secondary', !active);
      tab.dataset.rbvmTabState = active ? 'active' : 'inactive';
      tab.setAttribute('aria-pressed', active ? 'true' : 'false');
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
    const candidates = document.querySelectorAll('.badge, .pill, .tag, .chip, .status-pill, td');
    candidates.forEach(node => {
      const state = stateMap.get(node.textContent.trim().toUpperCase());
      if (state) node.dataset.rbvmState = state;
    });
    document.querySelectorAll('.status.error, [role="status"].error, [data-state="error"]').forEach(node => {
      node.dataset.rbvmState = 'error';
    });
    document.querySelectorAll('.status.success, [role="status"].success, [role="status"].ok, [data-state="success"]').forEach(node => {
      node.dataset.rbvmState = 'success';
    });
  }

  function observeSemanticStates() {
    if (!document.body || typeof MutationObserver !== 'function') return;
    const observer = new MutationObserver(() => {
      normalizeSemanticStates();
      normalizeGuideTabs();
      normalizeAuthMessages();
    });
    observer.observe(document.body, {subtree: true, childList: true, characterData: true, attributes: true, attributeFilter: ['class', 'data-state']});
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
    footer.innerHTML = '<span><strong>RBVM</strong> · منصة قرارات المخاطر المبنية على الدليل</span><span class="rbvm-page-footer__meta"><span>واجهة تشغيل موحّدة</span><span aria-hidden="true">·</span><code>RBVM_FRONTEND_SYSTEM_V1</code></span>';
    document.body.append(footer);
  }

  function init() {
    applyTheme(readTheme());
    document.documentElement.dataset.rbvmFrontend = FRONTEND_CONTRACT;
    markPageIdentity();
    createShell();
    const main = normalizeMain();
    normalizeLegacyHero(main);
    enhanceHero(main);
    normalizeModules(main);
    normalizeLegacyAuth();
    localizeInterface();
    normalizeAuthMessages();
    normalizeTables();
    normalizeExternalState();
    normalizeGuideTabs();
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
