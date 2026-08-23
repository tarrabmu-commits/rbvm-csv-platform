(() => {
  'use strict';

  const CONTRACT = 'CSV_RUN_DECISION_VISUALS_V1';
  const PRIORITY_METHOD = 'RBVM_MVP_PRIORITY_POLICY_V1';
  const PRIORITY_SHA = '88d5cdb8702c6c0ed2c033c3df6b8abbe1aa392f44f4507685b54082a16dc388';
  document.documentElement.dataset.csvRunDecisionVisuals = CONTRACT;

  const h = (tag, attrs = {}, ...children) => {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(attrs)) {
      if (value === null || value === undefined || value === false) continue;
      if (key === 'class') node.className = value;
      else if (key === 'text') node.textContent = String(value);
      else if (key === 'style') node.style.cssText = String(value);
      else if (key in node && !key.startsWith('aria') && !key.startsWith('data-')) node[key] = value;
      else node.setAttribute(key, String(value));
    }
    for (const child of children.flat()) {
      if (child === null || child === undefined || child === false) continue;
      node.append(child instanceof Node ? child : document.createTextNode(String(child)));
    }
    return node;
  };

  const svg = (tag, attrs = {}, ...children) => {
    const node = document.createElementNS('http://www.w3.org/2000/svg', tag);
    for (const [key, value] of Object.entries(attrs)) {
      if (value === null || value === undefined || value === false) continue;
      node.setAttribute(key, String(value));
    }
    for (const child of children.flat()) {
      if (child === null || child === undefined || child === false) continue;
      node.append(child);
    }
    return node;
  };

  const num = value => Number(value ?? 0).toLocaleString('en-US');
  const pct = (value, digits = 1) => Number.isFinite(Number(value)) ? `${(Number(value) * 100).toFixed(digits)}%` : '—';
  const upper = value => String(value || 'UNKNOWN').trim().toUpperCase();
  const title = value => String(value || '').toLowerCase().replace(/(^|[_\s-])\w/g, part => part.toUpperCase()).replaceAll('_', ' ');
  const finite = value => Number.isFinite(Number(value)) ? Number(value) : null;
  const clamp = (value, min, max) => Math.min(max, Math.max(min, value));

  function countBy(rows, getter) {
    const out = new Map();
    for (const row of rows) {
      const key = getter(row) || 'UNKNOWN';
      out.set(key, (out.get(key) || 0) + 1);
    }
    return out;
  }

  function panel(name, subtitle, body, badge = '', wide = false) {
    return h('section', {class: `runviz-card${wide ? ' runviz-wide' : ''}`},
      h('div', {class: 'runviz-card-header'},
        h('div', {}, h('h3', {text: name}), subtitle ? h('p', {text: subtitle}) : null),
        badge ? h('span', {class: 'runviz-badge', text: badge}) : null
      ),
      h('div', {class: 'runviz-card-body'}, body)
    );
  }

  function donut(items, centerValue, centerLabel, ariaLabel) {
    const total = items.reduce((sum, item) => sum + Number(item.value || 0), 0);
    if (!total) return h('p', {class: 'runviz-muted', text: 'No data available.'});
    const radius = 66;
    const circumference = 2 * Math.PI * radius;
    let offset = 0;
    const chart = svg('svg', {viewBox: '0 0 210 210', class: 'runviz-donut', role: 'img', 'aria-label': ariaLabel});
    chart.append(svg('circle', {cx: 105, cy: 105, r: radius, fill: 'none', 'stroke-width': 26, class: 'runviz-donut-track'}));
    for (const item of items) {
      const value = Number(item.value || 0);
      if (!value) continue;
      const length = circumference * value / total;
      const segment = svg('circle', {
        cx: 105, cy: 105, r: radius, fill: 'none', 'stroke-width': 26,
        class: `runviz-donut-segment ${item.css || ''}`.trim(),
        'stroke-dasharray': `${length} ${circumference - length}`,
        'stroke-dashoffset': -offset,
        transform: 'rotate(-90 105 105)'
      });
      segment.append(svg('title', {}, document.createTextNode(`${item.label}: ${num(value)}`)));
      chart.append(segment);
      offset += length;
    }
    chart.append(svg('text', {x: 105, y: 100, 'text-anchor': 'middle', class: 'runviz-donut-value'}, document.createTextNode(String(centerValue))));
    chart.append(svg('text', {x: 105, y: 122, 'text-anchor': 'middle', class: 'runviz-donut-label'}, document.createTextNode(centerLabel)));
    return h('div', {class: 'runviz-donut-wrap'}, chart,
      h('div', {class: 'runviz-legend'}, ...items.map(item =>
        h('span', {}, h('i', {class: `runviz-dot ${item.css || ''}`.trim()}), `${item.label} · ${num(item.value)}`)
      ))
    );
  }

  function bars(items, format = value => num(value), emptyText = 'No data available.') {
    if (!items.length || !items.some(item => Number(item.value) > 0)) return h('p', {class: 'runviz-muted', text: emptyText});
    const max = Math.max(1, ...items.map(item => Number(item.value) || 0));
    return h('div', {class: 'runviz-bars'}, ...items.map(item => {
      const value = Number(item.value) || 0;
      const fill = h('span', {class: `runviz-bar-fill ${item.css || ''}`.trim()});
      fill.style.width = `${Math.max(value ? 2 : 0, value / max * 100)}%`;
      return h('div', {class: 'runviz-bar-row'},
        h('span', {class: 'runviz-bar-label', title: item.label, text: item.label}),
        h('span', {class: 'runviz-bar-track'}, fill),
        h('strong', {text: format(value)})
      );
    }));
  }

  function priorityFront(row) {
    if (row.RBVM_MVP_Priority_Status !== 'RANKED_RELATIVE_ONLY') return null;
    const value = Number(row.RBVM_MVP_Priority_Front);
    return Number.isInteger(value) && value > 0 ? value : null;
  }

  function priorityDistribution(rows, report) {
    const fronts = report?.frontCounts && typeof report.frontCounts === 'object'
      ? Object.entries(report.frontCounts).map(([front, value]) => ({
          label: `Front ${front}`,
          value: Number(value || 0),
          css: `runviz-front-${Math.min(5, Number(front) || 5)}`,
        }))
      : [...countBy(rows.filter(row => priorityFront(row) !== null), row => `Front ${priorityFront(row)}`).entries()]
          .map(([label, value]) => ({label, value, css: `runviz-front-${Math.min(5, Number(label.replace('Front ', '')) || 5)}`}));
    fronts.sort((a, b) => Number(a.label.replace('Front ', '')) - Number(b.label.replace('Front ', '')));
    const unrankable = Number(report?.unrankableRows ?? rows.filter(row => row.RBVM_MVP_Priority_Status === 'UNRANKABLE_MISSING_EVIDENCE').length);
    const items = [...fronts, {label: 'Unrankable', value: unrankable, css: 'runviz-unrankable'}];
    return donut(items, num(rows.length), 'findings', 'MVP relative treatment priority distribution');
  }

  const BLOCKER_LABELS = {
    KEV_STATE_MISSING_OR_INVALID: 'CISA KEV state',
    INTERNET_FACING_MISSING_OR_INVALID: 'Internet Facing',
    ASSET_CRITICALITY_MISSING_OR_INVALID: 'Asset Criticality',
    EPSS_MISSING_OR_INVALID: 'FIRST EPSS',
    CVSS4_CONTEXT_SCORE_MISSING_OR_INVALID: 'Contextual CVSS v4',
  };

  function blockerRows(rows, report) {
    const counts = new Map();
    const source = report?.unrankableReasons && typeof report.unrankableReasons === 'object'
      ? Object.entries(report.unrankableReasons)
      : null;
    if (source) {
      for (const [code, value] of source) counts.set(code, Number(value || 0));
    } else {
      for (const row of rows) {
        for (const code of String(row.RBVM_MVP_Priority_Blockers || '').split('|').filter(Boolean)) {
          counts.set(code, (counts.get(code) || 0) + 1);
        }
      }
    }
    return [...counts.entries()]
      .map(([code, value]) => ({label: BLOCKER_LABELS[code] || title(code), value, css: 'runviz-blocker'}))
      .sort((a, b) => b.value - a.value || a.label.localeCompare(b.label));
  }

  function contextualScatter(rows) {
    const points = rows.map(row => ({
      cve: row.CVE_ID || 'Unknown',
      asset: row.Agent || row.Agent_ID || 'Unknown asset',
      epss: finite(row.EPSS_Probability),
      cvss: finite(row.CVSS4_Context_Score),
      kev: String(row.KEV_Listed || '').trim().toLowerCase() === 'true',
      front: priorityFront(row),
    })).filter(point => point.epss !== null && point.cvss !== null);
    if (!points.length) return h('p', {class: 'runviz-muted', text: 'No rows have both contextual CVSS v4 and EPSS.'});

    const width = 760, height = 365, left = 58, right = 24, top = 24, bottom = 50;
    const plotW = width - left - right, plotH = height - top - bottom;
    const chart = svg('svg', {viewBox: `0 0 ${width} ${height}`, class: 'runviz-scatter', role: 'img', 'aria-label': 'Contextual CVSS v4 by FIRST EPSS probability'});
    for (let step = 0; step <= 5; step++) {
      const x = left + plotW * step / 5;
      chart.append(svg('line', {x1: x, y1: top, x2: x, y2: top + plotH, class: 'runviz-grid-line'}));
      chart.append(svg('text', {x, y: height - 20, 'text-anchor': 'middle', class: 'runviz-axis-text'}, document.createTextNode(`${step * 20}%`)));
      const score = step * 2;
      const y = top + plotH - plotH * score / 10;
      chart.append(svg('line', {x1: left, y1: y, x2: left + plotW, y2: y, class: 'runviz-grid-line'}));
      chart.append(svg('text', {x: left - 11, y: y + 4, 'text-anchor': 'end', class: 'runviz-axis-text'}, document.createTextNode(String(score))));
    }
    chart.append(svg('text', {x: left + plotW / 2, y: height - 2, 'text-anchor': 'middle', class: 'runviz-axis-label'}, document.createTextNode('FIRST EPSS probability · next 30 days')));
    chart.append(svg('text', {x: 15, y: top + plotH / 2, 'text-anchor': 'middle', transform: `rotate(-90 15 ${top + plotH / 2})`, class: 'runviz-axis-label'}, document.createTextNode('Contextual CVSS v4 technical severity')));

    for (const point of points) {
      const cx = left + plotW * clamp(point.epss, 0, 1);
      const cy = top + plotH - plotH * clamp(point.cvss, 0, 10) / 10;
      if (point.front === 1) {
        chart.append(svg('circle', {cx, cy, r: 8, class: 'runviz-front1-ring'}));
      }
      const dot = svg('circle', {cx, cy, r: point.kev ? 5.5 : 4.5, class: point.kev ? 'runviz-point runviz-point-kev' : 'runviz-point'});
      dot.append(svg('title', {}, document.createTextNode(
        `${point.cve} · ${point.asset}\nEPSS ${pct(point.epss)} · Contextual CVSS v4 ${point.cvss.toFixed(1)}${point.kev ? ' · KEV listed' : ''}${point.front ? ` · Front ${point.front}` : ' · Unrankable'}`
      )));
      chart.append(dot);
    }
    return h('div', {class: 'runviz-scatter-wrap'}, chart,
      h('div', {class: 'runviz-legend'},
        h('span', {}, h('i', {class: 'runviz-dot runviz-point-legend'}), 'Not KEV-listed / not established'),
        h('span', {}, h('i', {class: 'runviz-dot runviz-point-kev'}), 'CISA KEV listed'),
        h('span', {}, h('i', {class: 'runviz-ring-legend'}), 'Front 1 Pareto outcome')
      )
    );
  }

  function dominanceScatter(rows) {
    const points = rows.map(row => ({
      cve: row.CVE_ID || 'Unknown', asset: row.Agent || row.Agent_ID || 'Unknown asset',
      dominates: finite(row.RBVM_MVP_Priority_Dominates),
      dominatedBy: finite(row.RBVM_MVP_Priority_Dominated_By),
      front: priorityFront(row),
    })).filter(point => point.front !== null && point.dominates !== null && point.dominatedBy !== null);
    if (!points.length) return h('p', {class: 'runviz-muted', text: 'No ranked Pareto relationships are available.'});

    const maxX = Math.max(1, ...points.map(point => point.dominates));
    const maxY = Math.max(1, ...points.map(point => point.dominatedBy));
    const width = 650, height = 330, left = 54, right = 24, top = 26, bottom = 50;
    const plotW = width - left - right, plotH = height - top - bottom;
    const chart = svg('svg', {viewBox: `0 0 ${width} ${height}`, class: 'runviz-scatter', role: 'img', 'aria-label': 'Pareto dominance relationship landscape'});

    for (let step = 0; step <= 4; step++) {
      const xValue = Math.round(maxX * step / 4);
      const x = left + plotW * step / 4;
      chart.append(svg('line', {x1: x, y1: top, x2: x, y2: top + plotH, class: 'runviz-grid-line'}));
      chart.append(svg('text', {x, y: height - 20, 'text-anchor': 'middle', class: 'runviz-axis-text'}, document.createTextNode(String(xValue))));
      const yValue = Math.round(maxY * step / 4);
      const y = top + plotH - plotH * step / 4;
      chart.append(svg('line', {x1: left, y1: y, x2: left + plotW, y2: y, class: 'runviz-grid-line'}));
      chart.append(svg('text', {x: left - 10, y: y + 4, 'text-anchor': 'end', class: 'runviz-axis-text'}, document.createTextNode(String(yValue))));
    }
    chart.append(svg('text', {x: left + plotW / 2, y: height - 2, 'text-anchor': 'middle', class: 'runviz-axis-label'}, document.createTextNode('Rows dominated by this finding')));
    chart.append(svg('text', {x: 14, y: top + plotH / 2, 'text-anchor': 'middle', transform: `rotate(-90 14 ${top + plotH / 2})`, class: 'runviz-axis-label'}, document.createTextNode('Rows dominating this finding')));

    for (const point of points) {
      const cx = left + plotW * point.dominates / maxX;
      const cy = top + plotH - plotH * point.dominatedBy / maxY;
      const dot = svg('circle', {cx, cy, r: point.front === 1 ? 6.5 : 5, class: `runviz-pareto-point runviz-front-${Math.min(5, point.front)}`});
      dot.append(svg('title', {}, document.createTextNode(`${point.cve} · ${point.asset}\nFront ${point.front} · dominates ${point.dominates} · dominated by ${point.dominatedBy}`)));
      chart.append(dot);
    }
    return h('div', {}, chart,
      h('p', {class: 'runviz-footnote', text: 'This chart visualizes the policy’s actual dominance relationships. It does not create a secondary score or reorder findings inside a Pareto front.'})
    );
  }

  function dynamicEvidenceBars(rows, field, css) {
    const counts = countBy(rows.filter(row => String(row[field] || '').trim()), row => upper(row[field]));
    return [...counts.entries()]
      .map(([label, value]) => ({label: title(label), value, css}))
      .sort((a, b) => b.value - a.value || a.label.localeCompare(b.label));
  }

  function ssvcEvidence(rows) {
    const dimensions = [
      ['Exploitation', 'CISA_Exploitation', 'runviz-ssvc-exploitation'],
      ['Automatable', 'CISA_Automatable', 'runviz-ssvc-automatable'],
      ['Technical Impact', 'CISA_Technical_Impact', 'runviz-ssvc-impact'],
    ];
    const body = h('div', {class: 'runviz-ssvc'});
    let populated = false;
    for (const [label, field, css] of dimensions) {
      const values = dynamicEvidenceBars(rows, field, css);
      if (values.length) populated = true;
      body.append(h('div', {class: 'runviz-ssvc-group'}, h('strong', {text: label}), bars(values, value => num(value), 'No evidence reported.')));
    }
    if (!populated) return h('p', {class: 'runviz-muted', text: 'No CISA Vulnrichment SSVC evidence dimensions are available for this run.'});
    body.append(h('p', {class: 'runviz-footnote', text: 'These are CISA Vulnrichment SSVC evidence dimensions only. RBVM does not infer a Track / Track* / Attend / Act decision unless an explicit decision output is supplied.'}));
    return body;
  }

  function contextMatrix(rows) {
    const criticalities = ['MISSION_CRITICAL', 'HIGH', 'MODERATE', 'LOW', 'UNKNOWN'];
    const exposures = ['YES', 'NO', 'UNKNOWN'];
    const values = criticalities.flatMap(criticality => exposures.map(exposure => rows.filter(row => upper(row.Asset_Criticality) === criticality && upper(row.Internet_Facing) === exposure).length));
    const max = Math.max(1, ...values);
    const grid = h('div', {class: 'runviz-matrix', role: 'table', 'aria-label': 'Customer Asset Criticality by Internet Facing'});
    grid.append(h('div', {class: 'runviz-matrix-corner'}));
    exposures.forEach(exposure => grid.append(h('div', {class: 'runviz-matrix-heading', text: exposure === 'YES' ? 'Internet YES' : exposure === 'NO' ? 'Internet NO' : 'Unknown'})));
    for (const criticality of criticalities) {
      grid.append(h('div', {class: 'runviz-matrix-row-label', text: title(criticality)}));
      for (const exposure of exposures) {
        const value = rows.filter(row => upper(row.Asset_Criticality) === criticality && upper(row.Internet_Facing) === exposure).length;
        grid.append(h('div', {class: 'runviz-matrix-cell', style: `--runviz-heat:${(value / max).toFixed(4)}`, title: `${title(criticality)} · Internet ${exposure}: ${value}`}, h('strong', {text: num(value)})));
      }
    }
    return h('div', {}, grid, h('p', {class: 'runviz-footnote', text: 'Both dimensions are direct customer context attached to the same analysis row. Internet Facing remains asset-level context and is not exact finding/endpoint reachability.'}));
  }

  function environmentalProfile(rows) {
    const dimensions = [['CR', 'CVSS4_CR_Resolved'], ['IR', 'CVSS4_IR_Resolved'], ['AR', 'CVSS4_AR_Resolved']];
    const values = ['H', 'M', 'L', 'X'];
    const wrap = h('div', {class: 'runviz-env'});
    for (const [label, field] of dimensions) {
      const counts = countBy(rows, row => upper(row[field]));
      wrap.append(h('div', {class: 'runviz-env-group'},
        h('strong', {text: label}),
        h('div', {class: 'runviz-env-stack'}, ...values.map(value => {
          const count = counts.get(value) || 0;
          const segment = h('span', {class: `runviz-env-segment runviz-env-${value.toLowerCase()}`, title: `${label}:${value} · ${count}`});
          segment.style.flexGrow = String(count);
          if (!count) segment.style.display = 'none';
          return segment;
        })),
        h('div', {class: 'runviz-env-legend'}, ...values.map(value => h('span', {text: `${value} ${num(counts.get(value) || 0)}`})))
      ));
    }
    wrap.append(h('p', {class: 'runviz-footnote', text: 'CR / IR / AR are direct customer CVSS v4 Security Requirements. Asset Criticality is not mapped into them.'}));
    return wrap;
  }

  function contextMode(rows) {
    const order = ['CVSS-B', 'CVSS-BT', 'CVSS-BE', 'CVSS-BTE', 'UNAVAILABLE'];
    const counts = countBy(rows, row => String(row.CVSS4_Context_Nomenclature || '').trim() || 'UNAVAILABLE');
    const items = order.map((key, index) => ({label: key, value: counts.get(key) || 0, css: `runviz-context-${index + 1}`}));
    for (const [label, value] of counts.entries()) {
      if (!order.includes(label)) items.push({label, value, css: 'runviz-context-other'});
    }
    return donut(items, num(rows.length), 'findings', 'Contextual CVSS v4 nomenclature distribution');
  }

  function methodAdmission(admission) {
    const selection = admission?.selection || {};
    const candidates = Array.isArray(admission?.candidates) ? admission.candidates : [];
    const state = selection.state || 'UNKNOWN';
    const body = h('div', {class: 'runviz-admission'},
      h('div', {class: `runviz-admission-state ${state === 'NO_V2_PRIMARY_METHOD_ADMITTED' ? 'runviz-admission-warning' : ''}`},
        h('span', {text: 'Selection'}), h('strong', {text: state})
      )
    );
    if (candidates.length) {
      body.append(h('div', {class: 'runviz-candidates'}, ...candidates.map(candidate =>
        h('div', {class: 'runviz-candidate'},
          h('strong', {text: candidate.methodId || candidate.methodFamily || 'Undefined method'}),
          h('span', {text: candidate.admissionState || 'UNKNOWN'}),
          h('small', {text: `${Number(candidate.riskComputedRows || 0)} risk row(s)`})
        )
      )));
    }
    body.append(h('p', {class: 'runviz-footnote', text: 'Admission states are categorical method-contract results, not numeric scores. The dashboard does not rank candidates by display order.'}));
    return body;
  }

  function validate(rows, report) {
    if (!Array.isArray(rows) || !rows.length) throw new Error('CSV run decision visuals require ranked finding rows.');
    if (!report || report.methodId !== PRIORITY_METHOD || report.methodSha256 !== PRIORITY_SHA) {
      throw new Error('CSV run decision visuals require the pinned MVP priority report.');
    }
    if (report.organizationalRiskComputed !== false || report.riskStatus !== 'NON_COMPUTABLE') {
      throw new Error('Priority report risk semantics are incompatible with this visualization contract.');
    }
    for (const row of rows) {
      const sha = String(row.RBVM_MVP_Priority_Method_SHA256 || '').trim();
      if (sha && sha !== PRIORITY_SHA) throw new Error('Finding row priority-policy SHA mismatch.');
    }
  }

  function render(rows, priorityReport, admission) {
    try {
      validate(rows, priorityReport);
      const ranked = Number(priorityReport.rankedRows || 0);
      const unrankable = Number(priorityReport.unrankableRows || 0);
      const root = h('section', {'data-csv-run-decision-visuals': 'true', class: 'runviz-root'},
        h('div', {class: 'runviz-header'},
          h('div', {}, h('div', {class: 'runviz-eyebrow', text: 'Decision evidence · exact CSV analysis scope'}), h('h3', {text: 'Treatment priority & evidence landscape'}), h('p', {text: 'Professional visualizations of admitted Pareto priority outputs and the exact evidence dimensions behind this immutable analysis.'})),
          h('div', {class: 'runviz-contract'}, h('strong', {text: PRIORITY_METHOD}), h('span', {text: 'Weight-free · threshold-free Pareto policy'}))
        ),
        h('div', {class: 'runviz-summary'},
          h('div', {}, h('span', {text: 'Ranked'}), h('strong', {text: num(ranked)})),
          h('div', {}, h('span', {text: 'Unrankable'}), h('strong', {text: num(unrankable)})),
          h('div', {}, h('span', {text: 'Front 1'}), h('strong', {text: num(priorityReport.frontCounts?.['1'] || 0)})),
          h('div', {}, h('span', {text: 'Organizational Risk'}), h('strong', {text: 'NON_COMPUTABLE'}))
        ),
        h('div', {class: 'runviz-grid'},
          panel('Pareto priority distribution', 'Front 1 is nondominated within this exact input set; it is not a risk rating or SLA.', priorityDistribution(rows, priorityReport), 'RBVM policy'),
          panel('Unrankable evidence blockers', 'Exact policy blockers. Missing evidence remains missing and is never imputed.', bars(blockerRows(rows, priorityReport), value => num(value), 'No rows are unrankable.'), 'Evidence readiness'),
          panel('Contextual CVSS v4 × EPSS', 'Independent technical-severity and exploitation-probability signals, with KEV and Front 1 highlighted.', contextualScatter(rows), 'FIRST + CISA', true),
          panel('Pareto dominance landscape', 'Actual dominates / dominated-by relationships emitted by the MVP policy.', dominanceScatter(rows), 'RBVM policy', true),
          panel('CISA SSVC evidence profile', 'Vulnrichment evidence dimensions are shown independently; no SSVC decision outcome is inferred.', ssvcEvidence(rows), 'CISA SSVC'),
          panel('Customer context matrix', 'Asset Criticality × Internet Facing for the exact matched analysis rows.', contextMatrix(rows), 'Customer context'),
          panel('CVSS v4 context modes', 'Distribution of the contextual technical-severity nomenclature actually calculated for this run.', contextMode(rows), 'FIRST CVSS v4'),
          panel('CVSS v4 Security Requirements', 'Direct customer CR / IR / AR declarations used only as CVSS v4 environmental requirements.', environmentalProfile(rows), 'Customer context'),
          panel('Organizational Risk method admission', 'Shows which candidate methods are reference-only, blocked, or not approved.', methodAdmission(admission), 'Method contract', true)
        ),
        h('div', {class: 'runviz-boundary'},
          h('strong', {text: 'Interpretation boundary'}),
          h('span', {text: 'No CVSS×EPSS multiplication · no hidden weights · no invented EPSS/CVSS threshold · no SSVC action inference · no Organizational Risk claim.'})
        )
      );
      return root;
    } catch (error) {
      return h('div', {class: 'callout callout-warning', text: `Decision visuals unavailable: ${error.message}`});
    }
  }

  window.rbvmCsvRunVisuals = Object.freeze({contractId: CONTRACT, render});
})();
