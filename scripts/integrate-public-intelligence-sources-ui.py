#!/usr/bin/env python3
"""Integrate Intelligence Sources into the dependency-free RBVM Frontend System V2 bundle.

The transform is intentionally exact and fail-closed. It changes the compiled runtime copy of
rbvm-ui.js only; it does not add a MutationObserver, monkey-patch fetch, or create a second UI
runtime. If the core frontend anchors drift, compilation stops instead of silently layering a
new surface on top of an unknown shell.
"""

from pathlib import Path
import sys


QUERY_OLD = "const QUERY_ROUTES = new Set(['/findings', '/analytics', '/reports', '/evidence', '/imports', '/settings']);"
QUERY_NEW = "const QUERY_ROUTES = new Set(['/findings', '/analytics', '/reports', '/evidence', '/imports', '/intelligence', '/settings']);"

NAV_OLD = "['Data', [['/evidence', 'Evidence', '◇'], ['/imports', 'Imports', '⇧']]],"
NAV_NEW = "['Data', [['/evidence', 'Evidence', '◇'], ['/imports', 'Imports', '⇧'], ['/intelligence', 'Intelligence', '◎']]],"

DISPATCH_OLD = "else if(current==='/imports')await renderImports();else if(current==='/settings')renderSettings();"
DISPATCH_NEW = "else if(current==='/imports')await renderImports();else if(current==='/intelligence')await renderIntelligence();else if(current==='/settings')renderSettings();"

INSERT_ANCHOR = "  function renderSettings(){"

INTEGRATION = r'''  const INTELLIGENCE_PROVIDERS = [
    ['NVD', 'NVD'],
    ['FIRST_EPSS', 'FIRST EPSS'],
    ['CISA_KEV', 'CISA KEV'],
    ['CVE_PROGRAM', 'CVE Program'],
  ];
  let intelligencePollTimer = null;
  let intelligenceNotice = '';

  function intelligenceOperationalState(row) {
    const latest = row?.latestJob || {};
    if (latest.status === 'RUNNING') return badge(`Running · ${title(latest.stage || 'ACQUIRING')}`, 'state-ambiguous');
    if (latest.status === 'FAILED') return badge('Latest refresh failed', 'state-stale');
    if (row?.neverSucceeded) return badge('Never synchronized', 'state-missing');
    return badge('Available locally', 'state-present');
  }

  function intelligenceAge(value) {
    if (!value) return 'Never';
    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) return String(value);
    const seconds = Math.max(0, Math.floor((Date.now() - parsed.getTime()) / 1000));
    if (seconds < 60) return `${seconds}s ago`;
    const minutes = Math.floor(seconds / 60);
    if (minutes < 60) return `${minutes}m ago`;
    const hours = Math.floor(minutes / 60);
    if (hours < 48) return `${hours}h ago`;
    return `${Math.floor(hours / 24)}d ago`;
  }

  async function triggerIntelligence(provider) {
    try {
      const response = await json(`/api/v1/intelligence/sync/${encodeURIComponent(provider)}`, {method: 'POST'});
      return {provider, state: 'accepted', response};
    } catch (error) {
      if (error.status === 409) return {provider, state: 'running'};
      throw error;
    }
  }

  async function updateIntelligenceProvider(provider) {
    try {
      const result = await triggerIntelligence(provider);
      intelligenceNotice = result.state === 'running'
        ? `${title(provider)} already has a synchronization job running.`
        : `${title(provider)} synchronization accepted. Status below is the persisted V31 job state.`;
    } catch (error) {
      intelligenceNotice = `Could not start ${title(provider)} synchronization: ${error.message}`;
    }
    await renderIntelligence();
  }

  async function updateAllIntelligence() {
    const results = await Promise.all(INTELLIGENCE_PROVIDERS.map(async ([provider]) => {
      try { return await triggerIntelligence(provider); }
      catch (error) { return {provider, state: 'failed', error}; }
    }));
    const accepted = results.filter(item => item.state === 'accepted').length;
    const running = results.filter(item => item.state === 'running').length;
    const failed = results.filter(item => item.state === 'failed');
    intelligenceNotice = failed.length
      ? `Started ${accepted} source refresh${accepted === 1 ? '' : 'es'}; ${running} already running; ${failed.length} could not be started. No failed start changes the last good local snapshot.`
      : `Started ${accepted} source refresh${accepted === 1 ? '' : 'es'}; ${running} already running. Status below comes from persisted V30/V31 state.`;
    await renderIntelligence();
  }

  function scheduleIntelligencePoll(rows) {
    if (intelligencePollTimer !== null) window.clearTimeout(intelligencePollTimer);
    intelligencePollTimer = null;
    if (!rows.some(row => row?.latestJob?.status === 'RUNNING')) return;
    intelligencePollTimer = window.setTimeout(() => {
      intelligencePollTimer = null;
      if (route() === '/intelligence') renderIntelligence();
    }, 1500);
  }

  async function renderIntelligence() {
    const root = clear(page());
    root.append(pageHeader(
      'Intelligence Sources',
      'Operate the shared local PostgreSQL mirror used by RBVM enrichment. Provider state is shown exactly as persisted; no freshness threshold or fake progress percentage is inferred.',
      [button('Update Intelligence Now', {kind: 'primary', onClick: updateAllIntelligence}), button('Refresh status', {kind: 'ghost', onClick: renderIntelligence})]
    ));
    const holder = h('div', {class: 'stack'}, loading());
    root.append(holder);
    try {
      const data = await json('/api/v1/intelligence/status');
      const byProvider = new Map((data.providers || []).map(row => [row.provider, row]));
      const rows = INTELLIGENCE_PROVIDERS.map(([provider, label]) => ({
        provider,
        label,
        ...(byProvider.get(provider) || {neverAttempted: true, neverSucceeded: true, latestJob: {}, lastSuccess: {}}),
      }));
      const running = rows.filter(row => row.latestJob?.status === 'RUNNING').length;
      const failed = rows.filter(row => row.latestJob?.status === 'FAILED').length;
      const never = rows.filter(row => row.neverSucceeded).length;
      const records = rows.reduce((sum, row) => sum + Number(row.lastSuccess?.recordCount || 0), 0);
      const notice = intelligenceNotice
        ? callout(intelligenceNotice, /could not|failed/i.test(intelligenceNotice) ? 'warning' : 'info')
        : callout('Update actions are asynchronous. Running stages and terminal outcomes come from the persisted V31 job lifecycle; last-success counts come from V30 source admission.');

      const sourceRows = table([
        {label: 'Source', render: row => h('strong', {text: row.label})},
        {label: 'Operational state', render: intelligenceOperationalState},
        {label: 'Last success', render: row => h('div', {}, h('strong', {text: intelligenceAge(row.lastSuccess?.completedAt)}), h('div', {class: 'timeline-meta', text: date(row.lastSuccess?.completedAt)}))},
        {label: 'Records', render: row => row.neverSucceeded ? '—' : num(row.lastSuccess?.recordCount || 0)},
        {label: 'Latest job', render: row => row.neverAttempted ? 'Never attempted' : `${title(row.latestJob?.status || 'UNKNOWN')} · ${title(row.latestJob?.stage || '—')}`},
        {label: 'Trigger', render: row => row.latestJob?.triggerSource ? title(row.latestJob.triggerSource) : '—'},
        {label: 'Action', render: row => button(row.latestJob?.status === 'RUNNING' ? 'Already running' : 'Update source', {kind: 'ghost', disabled: row.latestJob?.status === 'RUNNING', onClick: () => updateIntelligenceProvider(row.provider)})},
      ], rows, 'Public intelligence source status');

      const details = h('div', {class: 'stack'});
      rows.forEach(row => {
        const latest = row.latestJob || {};
        const success = row.lastSuccess || {};
        const failureText = latest.status === 'FAILED'
          ? callout(`Latest refresh failed${latest.errorCode ? ` · ${latest.errorCode}` : ''}${latest.errorDetail ? ` · ${latest.errorDetail}` : ''}. The last successful local snapshot remains authoritative.`, 'warning')
          : null;
        details.append(panel(
          row.label,
          row.neverSucceeded ? 'No successful local snapshot has been admitted yet.' : `Last successful source: ${success.sourceVersion || 'version unavailable'}`,
          h('div', {class: 'stack'},
            h('dl', {class: 'details-grid'},
              pair('Last success', date(success.completedAt)),
              pair('Observed at', date(success.observedAt)),
              pair('Sync mode', success.syncMode ? title(success.syncMode) : '—'),
              pair('Record count', row.neverSucceeded ? '—' : num(success.recordCount || 0)),
              pair('Source URI', success.sourceUri || '—', true),
              pair('Source version', success.sourceVersion || '—', true),
              pair('Source SHA-256', success.sourceSha256 || '—', true),
              pair('Latest job ID', latest.id || '—', true),
              pair('Latest job updated', date(latest.updatedAt))
            ),
            failureText
          )
        ));
      });

      holder.replaceChildren(
        h('div', {class: 'metrics'},
          metric('Providers', rows.length),
          metric('Running', running, 'Persisted V31 jobs'),
          metric('Latest failures', failed, 'Last good snapshot is retained'),
          metric('Local records', num(records), `${never} provider${never === 1 ? '' : 's'} never succeeded`)
        ),
        notice,
        panel('Source operations', `Status generated ${date(data.generatedAt)}. Age is descriptive only; RBVM does not invent a stale threshold.`, sourceRows),
        details
      );
      scheduleIntelligencePoll(rows);
    } catch (error) {
      if (intelligencePollTimer !== null) window.clearTimeout(intelligencePollTimer);
      intelligencePollTimer = null;
      holder.replaceChildren(error.status === 503
        ? callout('Public intelligence status requires the PostgreSQL V31 runtime. Existing customer evidence and findings are unchanged.', 'warning')
        : failure(error, renderIntelligence));
    }
  }

'''


def replace_exact(source: str, old: str, new: str, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected exactly one integration anchor, found {count}")
    return source.replace(old, new, 1)


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: integrate-public-intelligence-sources-ui.py <rbvm-ui.js>")
    path = Path(sys.argv[1])
    source = path.read_text(encoding="utf-8")
    if "PUBLIC_INTELLIGENCE_SOURCES_UI_V1" in source:
        raise RuntimeError("public-intelligence sources UI is already integrated")
    source = replace_exact(source, QUERY_OLD, QUERY_NEW, "query routes")
    source = replace_exact(source, NAV_OLD, NAV_NEW, "navigation")
    source = replace_exact(source, DISPATCH_OLD, DISPATCH_NEW, "route dispatch")
    count = source.count(INSERT_ANCHOR)
    if count != 1:
        raise RuntimeError(f"render insertion: expected exactly one integration anchor, found {count}")
    integration = "  const PUBLIC_INTELLIGENCE_SOURCES_UI_V1 = 'PUBLIC_INTELLIGENCE_SOURCES_UI_V1';\n" + INTEGRATION
    source = source.replace(INSERT_ANCHOR, integration + INSERT_ANCHOR, 1)
    path.write_text(source, encoding="utf-8")
    print("Public Intelligence Sources UI integration: PASS")


if __name__ == "__main__":
    main()
