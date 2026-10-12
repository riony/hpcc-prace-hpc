/* HPCC-PRACE fleet dashboard (roles/fleet_dashboard). Read-only: it fetches three JSON files from its
 * own origin and renders them. Every data string becomes a text node (textContent); markup is never
 * built from data; links are internal routes or same-origin GitLab paths made from numeric ids.
 * No inline script or style: the page runs under Content-Security-Policy default-src 'self'. */
'use strict';
(function () {
  var FILES = { latest: 30000, gitlab: 300000, evidence: 300000 };
  var OBS_AMBER = 180, OBS_RED = 900, GL_AMBER = 900;
  var TABS = [['cluster', 'Cluster'], ['slurm', 'Slurm'], ['scenarios', 'Scenarios'], ['cicd', 'CI/CD']];
  var S = { latest: null, gitlab: null, evidence: null, err: {}, got: {}, skew: 0, sel: { run: 0, ev: null, step: 0 } };

  /* ---- safe DOM construction ------------------------------------------------------------------ */
  var PLAIN = { 'class': 1, title: 1, id: 1, role: 1, hidden: 1, type: 1, disabled: 1, tabindex: 1, datetime: 1, scope: 1 };
  function h(tag, props) {
    var el = document.createElement(tag);
    if (props) Object.keys(props).forEach(function (k) { setProp(el, k, props[k]); });
    for (var i = 2; i < arguments.length; i++) add(el, arguments[i]);
    return el;
  }
  function add(el, kid) {
    if (kid === null || kid === undefined || kid === false) return;
    if (Array.isArray(kid)) { kid.forEach(function (k) { add(el, k); }); return; }
    el.appendChild(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  function setProp(el, k, v) {
    if (v === null || v === undefined || v === false) return;
    if (k === 'class') el.className = String(v);
    else if (k === 'href') {
      var s = String(v);
      if (/^#[A-Za-z0-9\/_.-]*$/.test(s) || /^\/[A-Za-z0-9\/_.-]+$/.test(s)) el.setAttribute('href', s);
    } else if (k === 'onclick') el.addEventListener('click', v);
    else if (k === 'width') el.style.width = v;          /* CSSOM, permitted by the CSP */
    else if (k === 'left') el.style.left = v;
    else if (PLAIN[k] || k.indexOf('aria-') === 0 || k.indexOf('data-') === 0) el.setAttribute(k, v === true ? '' : String(v));
    else throw new Error('attribute not allowed: ' + k);
  }
  function txt(v, dflt) { return v === null || v === undefined || v === '' ? (dflt === undefined ? ': ' : dflt) : String(v); }

  /* ---- time ------------------------------------------------------------------------------------ */
  function serverNow() { return (Date.now() - S.skew) / 1000; }
  function age(sec) {
    if (sec === null || sec === undefined || !isFinite(sec)) return 'unknown';
    sec = Math.max(0, Math.round(sec));
    if (sec < 90) return sec + ' s';
    if (sec < 5400) return Math.round(sec / 60) + ' min';
    if (sec < 172800) { var hr = Math.floor(sec / 3600); return hr + ' h ' + Math.round((sec - hr * 3600) / 60) + ' min'; }
    return Math.round(sec / 86400) + ' d';
  }
  function ago(t) { return t ? age(serverNow() - t) + ' ago' : 'not recorded'; }
  function when(t) {
    if (!t) return 'not recorded';
    try {
      return new Date(t * 1000).toLocaleString('en-GB', { timeZone: 'Asia/Singapore', year: 'numeric', month: '2-digit',
        day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }).replace(',', '') + ' SGT';
    } catch (e) { return new Date(t * 1000).toISOString(); }
  }
  function stamp(t) { return h('span', { title: when(t), 'data-t': t || '' }, ago(t)); }
  function tick() {   /* ages move between fetches without rebuilding the page */
    Array.prototype.forEach.call(document.querySelectorAll('[data-t]'), function (el) {
      var t = parseFloat(el.getAttribute('data-t'));
      if (isFinite(t) && t > 0) el.textContent = ago(t);
    });
    /* time alone can make data stale: rebuild when a freshness class changes, even with unchanged
       files or repeated failed fetches (review R1) */
    if (S.fresh !== undefined && freshness() !== S.fresh) render();
  }
  function freshness() {   /* every time-dependent class the page shows, from timestamps and the server clock */
    var L = S.latest, G = S.gitlab, now = serverNow(), m = L && L.monitor, obs = L && L.observation;
    return [m ? (now - m.last_run > OBS_AMBER ? 'monitor-stale' : 'monitor-fresh') : 'monitor-none',
      obs ? obsStale(obs) + ':' + ageClass(now - obs.time, OBS_AMBER, OBS_RED) : 'obs-none',
      G && G.generated_at ? (now - G.generated_at > GL_AMBER ? 'gitlab-stale' : 'gitlab-fresh') : 'gitlab-none'].join('|');
  }
  function obsStale(obs) {   /* the collector's flag, or the observation's own age against the current clock */
    if (!obs || obs.stale === true) return true;
    var a = serverNow() - obs.time;
    return !(isFinite(a) && a <= OBS_AMBER);
  }
  function dur(s) { return s === null || s === undefined ? ': ' : s < 120 ? Math.round(s) + ' s' : Math.round(s / 60) + ' min'; }

  /* ---- states: glyph and word, never colour alone -------------------------------------------- */
  var OUT = {
    HEALTHY: ['good', '✓', 'HEALTHY'], DRIFT: ['warn', '≠', 'DRIFT'],
    UNREACHABLE_OR_ERROR: ['crit', '✕', 'UNREACHABLE_OR_ERROR'], DEFERRED_MAINTENANCE: ['def', '◐', 'DEFERRED_MAINTENANCE'],
    UNHEALTHY: ['crit', '▲', 'UNHEALTHY']
  };
  var GEN = {
    ok: ['good', '✓'], warn: ['warn', '▲'], crit: ['crit', '✕'], def: ['def', '◐'],
    stale: ['stalec', '◷'], unk: ['unk', '?'], prop: ['unk', '◌']
  };
  function st(kind, word, badge) {
    var g = GEN[kind] || GEN.unk;
    return h('span', { 'class': (badge ? 'badge ' : 'st ') + g[0] }, h('span', { 'class': 'g', 'aria-hidden': 'true' }, g[1]), word);
  }
  function outcome(o, badge) {
    var d = OUT[o];
    if (!d) return st('unk', txt(o, 'unknown'), badge);
    return h('span', { 'class': (badge ? 'badge ' : 'st ') + d[0] }, h('span', { 'class': 'g', 'aria-hidden': 'true' }, d[1]), d[2]);
  }
  function yes(v, good, bad) { return v === true ? st('ok', good || 'yes') : v === false ? st('crit', bad || 'no') : st('unk', 'not observed'); }
  var JOB = { success: 'ok', failed: 'crit', canceled: 'unk', skipped: 'unk', manual: 'unk', running: 'def', pending: 'def', created: 'def' };

  /* ---- layout helpers ------------------------------------------------------------------------- */
  function card(title, opts, body) {
    opts = opts || {};
    var cls = 'card' + (opts.prov === 'proposed' ? ' proposed' : opts.prov === 'later' ? ' later' : '') + (opts.stale ? ' stale' : '') + (opts.cls ? ' ' + opts.cls : '');
    return h('section', { 'class': cls, 'aria-label': title },
      h('div', { 'class': 'card-head' }, h('h2', null, title),
        opts.prov === 'proposed' ? h('span', { 'class': 'ribbon' }, 'proposed collector') : null,
        opts.prov === 'later' ? h('span', { 'class': 'ribbon' }, 'later · owner decision') : null,
        opts.badge || null),
      body, opts.src ? h('div', { 'class': 'src' }, opts.src) : null);
  }
  function row(label, value, bad) { return h('div', { 'class': 'row' + (bad ? ' bad' : '') }, h('span', { 'class': 'l' }, label), h('span', { 'class': 'v' }, value)); }
  function table(head, rows) {
    return h('div', { 'class': 'scroll' }, h('table', { 'class': 't' },
      h('thead', null, h('tr', null, head.map(function (c) { return h('th', { scope: 'col' }, c); }))),
      h('tbody', null, rows.map(function (r) { return h('tr', null, r.map(function (c) { return h('td', null, c); })); }))));
  }
  function ctx(items) { return h('div', { 'class': 'ctx' }, items.map(function (i) { return h('span', null, h('span', { 'class': 'k' }, i[0]), i[1]); })); }
  function failed(name, what) {
    var e = S.err[name];
    if (!e && S[name]) return null;
    var build = S.evidence && S.evidence.build;
    if (build === 'workstation' && name !== 'evidence') return h('div', { 'class': 'errbar' }, st('unk', what + ': not part of the workstation build (served only from mgmt-git01).'));
    return h('div', { 'class': 'errbar' }, st('crit', what + ' unreadable: ' + (e || 'not loaded yet')), S[name] ? ' :  showing the last good copy.' : '');
  }
  function sourceErrors(doc) {
    if (!doc || !doc.errors || !doc.errors.length) return null;
    return h('div', { 'class': 'errbar' }, doc.errors.map(function (e) { return h('div', null, st('warn', e)); }));
  }
  function ageClass(sec, amber, red) { return sec === null ? 'unk' : sec > red ? 'crit' : sec > amber ? 'warn' : 'ok'; }

  /* ---- header and shell ----------------------------------------------------------------------- */
  function route() {
    var parts = (location.hash || '#cluster').slice(1).split('/');
    var tab = parts[0];
    if (tab === 'replay') {
      var actor = '';
      try { actor = decodeURIComponent(parts[2] || ''); } catch (e) { actor = ''; }   /* a malformed link must not blank the page */
      return { tab: 'replay', run: parseInt(parts[1], 10) || 0, actor: actor };
    }
    if (tab === 'scenarios') return { tab: tab, run: parseInt(parts[1], 10) || 0 };
    if (tab === 'play') return { tab: 'play', runId: /^[A-Za-z0-9_.-]{1,128}$/.test(parts[1] || '') ? parts[1] : '', name: /^[A-Za-z0-9_-]{1,64}$/.test(parts[2] || '') ? parts[2] : 'original' };
    return { tab: TABS.some(function (t) { return t[0] === tab; }) ? tab : 'cluster' };
  }
  function header(r) {
    var obs = S.latest && S.latest.observation;
    var oage = obs ? serverNow() - obs.time : null;
    var build = (S.evidence && S.evidence.build) || (S.latest && S.latest.build) || 'scrubbed';
    var active = r.tab === 'replay' || r.tab === 'play' ? 'scenarios' : r.tab;
    return h('header', { 'class': 'top' },
      h('div', { 'class': 'brand' }, h('b', null, 'HPCC-PRACE'), h('span', { 'class': 'mono muted' }, 'fleet dashboard')),
      h('nav', { 'class': 'tabs', 'aria-label': 'Sections' }, TABS.map(function (t) {
        return h('a', { href: '#' + t[0], 'aria-current': t[0] === active ? 'page' : null, 'data-key': 'tab-' + t[0] }, t[1]);
      })),
      h('div', { 'class': 'badges' },
        build === 'workstation' ? h('span', { 'class': 'chip private' }, 'Workstation · private, unscrubbed')
          : h('span', { 'class': 'chip scrubbed' }, 'Scrubbed view'),
        h('span', { 'class': 'chip' }, 'Read-only'),
        h('span', { 'class': 'chip', title: obs ? when(obs.time) : 'no raw observation' },
          st(oage === null ? 'unk' : ageClass(oage, OBS_AMBER, OBS_RED) === 'ok' ? 'ok' : 'stale', 'observed'),
          ' ', obs ? h('span', { 'data-t': obs.time }, ago(obs.time)) : ': '),
        h('button', { 'class': 'chip', type: 'button', title: 'Colour theme (kept in this browser only)', onclick: cycleTheme, 'data-key': 'theme' }, 'Theme: ' + theme())));
  }
  function footer() {
    var build = (S.evidence && S.evidence.build) || 'scrubbed';
    return h('footer', { 'class': 'foot' }, 'No control on this page acts on the fleet, Slurm, K3s, a BMC or GitLab. View: ',
      build === 'workstation' ? 'workstation build (private; never copied to mgmt-git01).' : 'scrubbed build served from mgmt-git01 (hostnames as roles, addresses, accounts and ids masked).');
  }
  function theme() { try { return localStorage.getItem('prace-dash-theme') || 'auto'; } catch (e) { return 'auto'; } }
  function applyTheme() { var t = theme(); if (t === 'auto') document.documentElement.removeAttribute('data-theme'); else document.documentElement.setAttribute('data-theme', t); }
  function cycleTheme() {
    var next = { auto: 'dark', dark: 'light', light: 'auto' }[theme()] || 'auto';
    try { localStorage.setItem('prace-dash-theme', next); } catch (e) { /* private mode: not kept */ }
    applyTheme(); render();
  }

  /* ---- Cluster -------------------------------------------------------------------------------- */
  function banner() {
    var L = S.latest, G = S.gitlab;
    if (!L) return failed('latest', 'Monitor data');
    var m = L.monitor, now = serverNow();
    var runAge = m ? now - m.last_run : null;
    var stale = runAge === null || runAge > OBS_AMBER;
    var d = m ? OUT[m.outcome] : null;
    var cls = stale ? 'stalec' : d ? d[0] : 'unk';
    var lease = L.lease || {};
    var drift = G && G.drift_audit && G.drift_audit.items && G.drift_audit.items.find(function (i) { return i.outcome || i.job_status; });
    var res = G && G.reservations && G.reservations.open;
    var facts = [
      row('Profile', L.profile ? 'deployed profile ' + L.profile.version + ' (from ' + L.profile.source_revision + '), ' + L.profile.workers + ' workers expected' : 'unreadable'),
      row('Monitor run', m ? stamp(m.last_run) : 'no state', stale),
      row('Raw observation', L.observation ? stamp(L.observation.time) : 'awaiting raw observation (monitor change MR 2a)'),
      row('Cluster lease', lease.held ? h('span', null, st('def', 'held'), ' ', txt(lease.holder), lease.label ? ' · ' + lease.label : '', ' · ', txt(lease.id), lease.since ? ' · since ' + when(lease.since) : '') :
        lease.stated ? st('ok', 'not held') : st('unk', 'not stated')),
      row('Window phase', h('span', { title: L.window ? L.window.text : '' }, txt(L.window && L.window.phase)), L.window && (L.window.phase === 'unexplained' || L.window.phase === 'unknown')),
      row('Monitor alert', m && m.alert_open ? st('crit', 'open' + (m.issue ? ' (issue ' + m.issue + ')' : '')) : st('ok', 'none open')),
      row('Reservation', !G ? 'GitLab data not loaded' : G.reservations && G.reservations.error ? st('crit', G.reservations.error) :
        res && res.length ? res.map(function (i) { return '#' + i.iid + ' ' + i.title; }).join('; ') : 'none open'),
      row('Last full drift audit (CI)', !G ? 'GitLab data not loaded' : drift ? h('span', null, outcome(drift.outcome || 'unknown', true), ' ', when(drift.created), ' (pipeline ' + drift.pipeline + ')') : 'no scheduled run found'),
      row('Main freeze', G && G.freeze ? h('span', null, G.freeze.state === 'frozen' ? st('def', 'frozen') : G.freeze.state === 'open' ? st('ok', 'open') : st('unk', 'unknown'), G.freeze.note ? ' · ' + G.freeze.note : '') : 'unknown')
    ];
    var word = d ? (m.outcome === 'DRIFT' ? 'DRIFT (structural)' : d[2]) : txt(m && m.outcome, 'unknown');
    return h('section', { 'class': 'card banner ' + cls, 'aria-label': 'Fleet status' },
      stale ? h('div', { 'class': 'stalebar' }, st('stale', 'STALE: the monitor has not run for ' + age(runAge) + '; the outcome below is its last one.')) : null,
      h('div', { 'class': 'outcome' }, h('span', { 'class': 'g ' + (d ? d[0] : 'unk'), 'aria-hidden': 'true' }, d ? d[1] : '?'), word,
        h('span', { 'class': 'small muted' }, 'off-node monitor, health only')),
      m && m.outcome === 'DRIFT' ? h('div', { 'class': 'small' }, 'Structural drift (node set or native list). Configuration drift is judged only by the nightly CI audit.') : null,
      m ? h('ul', { 'class': 'reasons' }, m.reasons.map(function (r) { return h('li', null, r); })) : null,
      h('div', { 'class': 'facts' }, facts),
      sourceErrors(L));
  }

  function hostCard(x, L) {
    var obs = L.observation, stale = obsStale(obs);
    var m = L.monitor || {};
    var bad = x.reasons && x.reasons.length && m.outcome !== 'DEFERRED_MAINTENANCE';
    var dot = !x.observed || stale ? '' : m.outcome === 'DEFERRED_MAINTENANCE' ? 'def' : bad ? 'crit' : 'good';
    var roleText = x.role === 'login' ? 'login · controller' : x.role + ' worker · ' + (x.kind || x.expected_kind) + (x.kind && x.kind !== x.expected_kind ? ' (expected ' + x.expected_kind + ')' : '');
    var inv = x.inventory;
    var rows = [];
    if (!x.observed) rows.push(row('Observation', obs ? 'not a Kubernetes node in the observation' : 'awaiting raw observation', !!obs));
    else {
      rows.push(row('Kubernetes', yes(x.k8s_ready, 'Ready', 'NotReady'), x.k8s_ready === false));
      if (x.role !== 'login') {
        if (x.native) {
          var n = x.native, u = n.slurmd || {};
          rows.push(row('slurmd (native)', n.error ? st('crit', n.error) : h('span', null, st(u.ActiveState === 'active' && u.SubState === 'running' ? 'ok' : 'crit',
            txt(u.ActiveState) + '/' + txt(u.SubState)), ' · ' + txt(u.UnitFileState) + ' · restarts ' + txt(u.NRestarts)), !!n.error));
          if (!n.error) {
            rows.push(row('Marker · key', txt(n.marker, 'none') + ' · key ' + txt(n.key)));
            Object.keys(n.mounts || {}).forEach(function (p) {
              var mm = n.mounts[p];
              rows.push(row('Host ' + p, (mm.lacks && mm.lacks.length ? 'lacks ' + mm.lacks.join(',') + ' · ' : '') + txt(mm.fstype) + ' ' + (mm.nfs || []).join(','), mm.lacks && mm.lacks.length));
            });
            rows.push(row('Native config hashes', txt(n.config_files) + ' files (drift verdict: nightly audit)'));
          }
        } else {
          rows.push(row('slurmd pod', x.slurmd_pods === 0 ? st('crit', 'none') : h('span', null, yes(x.slurmd_pod_ready, 'Ready', 'not Ready'), ' (' + txt(x.slurmd_pods) + ')'), x.slurmd_pod_ready !== true));
        }
        rows.push(row('Slurm', txt(x.slurm_state) + (x.slurm_gres && x.slurm_gres !== '(null)' ? ' · ' + x.slurm_gres : ''), ['idle', 'mixed', 'allocated', 'completing'].indexOf(x.slurm_state) < 0));
        rows.push(row('Pod network path', yes(x.pod_path, 'reachable', 'unreachable'), x.pod_path !== true));
      } else {
        rows.push(row('Tracked config', txt(x.config_files) + ' files hashed' + (x.config_missing ? ', ' + x.config_missing + ' missing/unreadable' : '') + ' · drift verdict: nightly audit'));
      }
      var sh = x.shares || [];
      var lacking = sh.filter(function (s) { return s.error || (s.lacks && Object.keys(s.lacks).length); });
      if (x.role === 'login' || !x.native) rows.push(row(x.role === 'login' ? 'Login pod shares' : 'Pod shares',
        !sh.length ? (m.outcome === 'DEFERRED_MAINTENANCE' && x.role === 'login' ? 'login pod down for maintenance' : 'not observed') :
        lacking.length ? st('crit', lacking.length + ' pod(s) lack nosuid/nodev/mode') : st('ok', sh.length + ' pod(s) guarded (nosuid, nodev, mode)'),
        lacking.length > 0 || (!sh.length && m.outcome !== 'DEFERRED_MAINTENANCE')));
    }
    var lk = x.links || {};
    rows.push(row('Disabled links', !lk.in_check ? 'not in the check' : lk.error ? st('crit', lk.error) : lk.alerts ? st('crit', lk.alerts + ' alert(s)') : st('ok', lk.down + '/' + lk.targets + ' down'), !!(lk.in_check && (lk.error || lk.alerts))));
    return h('article', { 'class': 'card' + (stale ? ' stale' : ''), 'aria-label': x.name },
      h('div', { 'class': 'host-head' }, h('span', { 'class': 'dot ' + dot, 'aria-hidden': 'true' }), h('b', { 'class': 'mono' }, x.name),
        h('span', { 'class': 'chip' }, roleText)),
      h('div', { 'class': 'inv', title: 'Static inventory held by the dashboard, from the repository; never read from the fleet' },
        inv ? 'static: ' + [inv.model, inv.bmc, inv.os, inv.gpus].filter(Boolean).join(' · ') : 'static inventory not set'),
      rows,
      x.reasons && x.reasons.length ? h('ul', { 'class': 'small crit' }, x.reasons.map(function (r) { return h('li', null, r); })) : null,
      stale && obs ? h('div', { 'class': 'src' }, st('stale', 'as of ' + when(obs.time))) : null);
  }

  function hostsSection() {
    var L = S.latest;
    if (!L) return failed('latest', 'Host data');
    return h('section', { 'aria-label': 'Hosts' }, h('div', { 'class': 'hosts' }, (L.hosts || []).map(function (x) { return hostCard(x, L); })),
      L.observation && L.observation.unknown_nodes ? h('p', { 'class': 'small warn' }, L.observation.unknown_nodes + ' Kubernetes node(s) outside the deployed profile (names withheld).') : null);
  }

  function guardCard() {
    var L = S.latest;
    if (!L) return null;
    var rows = [], alerts = 0;
    (L.network_guard || []).forEach(function (g) {
      if (!g.in_check) { rows.push([h('span', { 'class': 'mono nw' }, g.host), 'none', 'not in the check', ': ']); return; }
      alerts += g.alerts || 0;
      if (g.error && !(g.interfaces || []).length) { rows.push([h('span', { 'class': 'mono nw' }, g.host), ': ', st('crit', g.error), when(g.checked)]); return; }
      (g.interfaces || []).forEach(function (i) {
        rows.push([h('span', { 'class': 'mono nw' }, g.host), h('span', { 'class': 'mono' }, i.name),
          !i.observed ? st('crit', 'not observed') : h('span', null, i.down ? st('ok', 'down') : st('crit', 'UP or managed'),
            ' · admin ' + (i.admin_up ? 'up' : 'down') + ' · carrier ' + (i.carrier ? 'yes' : 'no') + ' · ' + txt(i.operstate) +
            ' · NM ' + (i.nm_managed ? 'managed' : 'unmanaged') + ' · ' + txt(i.addresses) + ' addr · identity ' + i.identity),
          when(g.checked)]);
      });
      if (g.error && (g.interfaces || []).length) rows.push([g.host, '', st('warn', g.error), '']);
    });
    return card('Network guard: links expected down', {
      badge: alerts ? st('crit', alerts + ' alert(s)', true) : st('ok', 'no alerts', true),
      src: 'D43 OS guard as the observer relays it (prace-disabled-links on each host). Lenovo has no guarded link. InfiniBand is not part of this check. An OS guard is not containment.'
    }, table(['Host', 'Link', 'Observed', 'Checked'], rows));
  }

  function recoveryCard() {
    var E = S.evidence;
    if (!E) return card('Recovery points', {}, failed('evidence', 'Evidence data'));
    var pts = (E.recovery_points || []).slice().reverse();
    var acc = pts.filter(function (p) { return p.accepted; });
    var last = acc[0];
    return card('Recovery points', { src: 'Metadata only, from committed recovery-point records (' + txt(E.source && E.source.commit && E.source.commit.slice(0, 12)) + '). Artifacts stay on the operator workstation (0600); their paths are never shown.' },
      [last ? [row('Latest accepted', txt(last.label, 'unlabelled') + ' · ' + last.id),
        row('Stage · phase', txt(last.stage) + ' · ' + txt(last.phase)),
        row('Revision', h('span', { 'class': 'mono' }, txt(last.revision && last.revision.slice(0, 12)))),
        row('Created', last.created ? h('span', null, when(last.created), ' (', ago(last.created), ')') : 'not recorded'),
        row('Artifacts', last.artifacts !== null ? last.artifacts + ' · ' + (last.bytes !== null ? (last.bytes / 1e6).toFixed(1) + ' MB' : 'size not recorded') : 'not recorded'),
        row('run.json', h('span', { 'class': 'mono' }, last.run_json_sha256 ? last.run_json_sha256.slice(0, 16) + '…' : 'not recorded'))]
        : h('div', { 'class': 'empty' }, st('warn', 'no accepted point in the verified evidence')),
      pts.length > 1 ? h('details', null, h('summary', null, pts.length + ' points in the evidence'),
        table(['Point', 'Stage', 'Accepted', 'Created', 'Folder'], pts.map(function (p) {
          return [txt(p.label, p.id), txt(p.stage), p.accepted ? st('ok', 'accepted') : st('warn', 'not accepted'), p.created ? when(p.created) : 'not recorded', h('span', { 'class': 'mono small' }, p.folder)];
        }))) : null]);
  }

  function transitionsCard() {
    var L = S.latest, G = S.gitlab;
    if (!L) return null;
    var hist = L.history;
    var rows = [];
    if (hist) {
      hist.transitions.slice().reverse().slice(0, 20).forEach(function (t) {
        rows.push([when(t.t), t.from ? outcome(t.from, true) : 'start of history', outcome(t.to, true), t.reasons.join('; ')]);
      });
    }
    var events = hist ? hist.events.slice().reverse().slice(0, 12) : [];
    var drift = G && G.drift_audit && G.drift_audit.items ? G.drift_audit.items[0] : null;
    return card('Monitor transitions (7 days)', {
      src: 'From the monitor’s own history.jsonl on mgmt-git01. The monitor reports HEALTHY, UNHEALTHY, UNREACHABLE_OR_ERROR, DEFERRED_MAINTENANCE, or DRIFT for structural reasons only. mgmt-git01 itself is not monitored (D39).'
    }, [hist ? null : failedLine('monitor history', L.errors),
      rows.length ? table(['When', 'From', 'To', 'Reasons'], rows) : h('div', { 'class': 'empty' }, 'No outcome change in the last 7 days.'),
      events.length ? [h('h3', null, 'Monitor events'), h('ul', { 'class': 'small' }, events.map(function (e) { return h('li', null, when(e.t) + ' · ' + e.event); }))] : null,
      drift ? h('p', { 'class': 'small' }, h('span', { 'class': 'k' }, 'CI, not monitor'), 'last scheduled drift audit: ', outcome(drift.outcome || 'unknown', true), ' ' + when(drift.created)) : null]);
  }
  function failedLine(what, errors) { return h('div', { 'class': 'errbar' }, st('warn', what + ' unavailable' + (errors && errors.length ? ': ' + errors.join('; ') : ''))); }

  function telemetry() {
    return h('div', { 'class': 'grid3' },
      card('GPU telemetry', { prov: 'proposed', src: 'Needs the observer extension (MR 5): nvidia-smi in each slurmd pod, actor-reachable, so labelled as such; or the host endpoint (MR 6). No values until it exists.' }, h('p', { 'class': 'muted' }, 'No collector yet.')),
      card('Host CPU, memory, disk, network', { prov: 'proposed', src: 'Needs the native-observe endpoint generalised to all five hosts (MR 6, only if wanted).' }, h('p', { 'class': 'muted' }, 'No collector yet.')),
      card('BMC sensors and SEL', { prov: 'later', src: 'Owner decision Q1. Would need a separate read-only BMC account; BMC login credentials never change.' }, h('p', { 'class': 'muted' }, 'Not collected.')));
  }

  function clusterTab() {
    return [ctx([['Source', 'the monitor’s state, history and raw observation on mgmt-git01 (no SSH session of the dashboard’s own)'],
      ['Evaluator', 'fleet_audit.py, health only, against the deployed profile'], ['Refresh', 'page 30 s · collector 60 s']]),
      banner(), hostsSection(), h('div', { 'class': 'grid2' }, guardCard(), recoveryCard()), transitionsCard(), telemetry()];
  }

  /* ---- Slurm ---------------------------------------------------------------------------------- */
  function partState(p, lease) {
    var s = String(p.state).toLowerCase();
    if (s === 'up') return st('ok', 'UP');
    if (s === 'inactive') return lease.held === true ? st('def', 'INACTIVE (lease held)')
      : lease.stated === true ? st('warn', 'INACTIVE without a lease') : st('unk', 'INACTIVE (lease not stated)');
    return st('crit', s.toUpperCase());
  }
  function leaseText(lease) {   /* only an explicit statement is "held" or "not held" (review R2) */
    if (lease.stated === true && lease.held === true) return txt(lease.holder) + ' · ' + txt(lease.label) + ' · ' + txt(lease.id);
    if (lease.stated === true && lease.held === false) return 'not held';
    return st('unk', 'not stated');
  }
  function stripView(hist) {
    if (!hist || !hist.strip_24h || !hist.strip_24h.length) return h('div', { 'class': 'empty' }, 'No monitor history for the last 24 h.');
    var end = serverNow(), start = end - 86400, segs = hist.strip_24h;
    var fill = { HEALTHY: 'good', DEFERRED_MAINTENANCE: 'def', UNHEALTHY: 'crit', UNREACHABLE_OR_ERROR: 'crit', DRIFT: 'warn' };
    var bar = h('div', { 'class': 'strip', role: 'img', 'aria-label': 'Monitor outcome over the last 24 hours' });
    var first = Math.max(segs[0].from, start);
    if (first > start) bar.appendChild(h('span', { 'class': 'fill-unk', width: ((first - start) / 864) + '%', title: 'no history' }));
    segs.forEach(function (s, i) {
      var a = Math.max(s.from, start), b = i + 1 < segs.length ? segs[i + 1].from : end;
      if (b > a) bar.appendChild(h('span', { 'class': 'fill-' + (fill[s.outcome] || 'unk'), width: ((b - a) / 864) + '%', title: s.outcome + ' from ' + when(s.from) }));
    });
    return [bar, h('div', { 'class': 'axis' }, h('span', null, '24 h ago'), h('span', null, 'now')),
      h('p', { 'class': 'small muted' }, 'Colour key, with words: green HEALTHY, violet DEFERRED_MAINTENANCE (lease held), red UNHEALTHY or UNREACHABLE_OR_ERROR, amber structural DRIFT, grey no history. Hover a segment for its outcome and start.'),
      hist.gaps_24h && hist.gaps_24h.length ? h('p', { 'class': 'small warn' }, hist.gaps_24h.length + ' gap(s) of more than 5 min between monitor runs.') : null];
  }
  function slurmTab() {
    var L = S.latest, E = S.evidence;
    var lease = (L && L.lease) || {};
    var parts = L ? card('Partitions', { src: 'sinfo %R|%a in the controller pod, as the observer reports it. Node lists per partition are not observed.' },
      L.partitions.length ? table(['Partition', 'State', 'Expected (profile)'], L.partitions.map(function (p) { return [h('span', { 'class': 'mono' }, p.name), partState(p, lease), txt(p.expected, 'not in the profile')]; }))
        : h('div', { 'class': 'empty' }, 'Partition states not observed.')) : failed('latest', 'Monitor data');
    var maint = L ? card('Maintenance today', { src: 'Window phase derived from the lease and the partition states; the window tool itself is not observed. During a lease the monitor reports DEFERRED_MAINTENANCE by design.' },
      [row('Lease', leaseText(lease), lease.stated !== true),
        row('Window phase', txt(L.window && L.window.text), L.window && (L.window.phase === 'unexplained' || L.window.phase === 'unknown')),
        stripView(L.history),
        h('p', { 'class': 'small muted' }, 'Window steps (tools/slurm-window.py): lease taken → close (partitions INACTIVE) → check → open → lease released. UNHEALTHY between a native switch and the next profile promotion is expected and recorded, not hidden.'),
        L.history && L.history.events.length ? h('ul', { 'class': 'small' }, L.history.events.slice(-8).reverse().map(function (e) { return h('li', null, when(e.t) + ' · ' + e.event); })) : null]) : null;
    var policy = L ? card('Policy and configuration values', { src: 'scontrol show config in the controller pod (observed) against the deployed profile; the GPU share is static, from the repository.' },
      [table(['Setting', 'Observed', 'Expected'], L.slurm_config.map(function (c) {
        return [h('span', { 'class': 'mono' }, c.key), h('span', { 'class': 'mono' }, txt(c.value)), c.expected === null || c.expected === undefined ? 'not judged' : c.value === c.expected ? st('ok', 'matches') : st('crit', 'expected ' + c.expected)];
      })), staticPolicy(L.static)]) : null;
    var acc = E ? acceptanceCard(E) : card('Acceptance runs', {}, failed('evidence', 'Evidence data'));
    return [ctx([['Objects', 'Slinky controller pod, LoginSet, NodeSets'], ['Exists', 'partitions, configuration values, acceptance outputs'], ['Needs a collector', 'allocation, queue, accounting, fairshare, pay-per-use (all read in the controller pod)']]),
      h('div', { 'class': 'grid2' }, parts, maint), policy,
      h('div', { 'class': 'grid3' },
        card('Nodes and allocation', { prov: 'proposed', src: 'sinfo -N -O … in slurm-controller-0 (observer extension, MR 5).' }, h('p', { 'class': 'muted' }, 'No collector yet.')),
        card('Queue and recent jobs', { prov: 'proposed', src: 'squeue and sacct in the controller pod, never the login pod. slurmrestd is declined: it would put a JWT on the management VM.' }, h('p', { 'class': 'muted' }, 'No collector yet.')),
        card('Fairshare and pay-per-use credits', { prov: 'proposed', src: 'sshare and the payg QoS in the controller pod.' }, h('p', { 'class': 'muted' }, 'No collector yet.'))),
      acc];
  }
  function staticPolicy(s) {
    var p = s && s.policy;
    if (!p) return null;
    return h('div', { 'class': 'small muted', title: 'static, from the repository at deploy time' },
      h('h3', null, 'Static, from the repository'), Object.keys(p).map(function (k) { return row(k, txt(p[k])); }));
  }
  function acceptanceCard(E) {
    var rows = (E.acceptance || []).map(function (r) {
      var res = r.result === 'passed' ? st('ok', 'passed') : r.result === 'stopped' ? st('warn', 'stopped') : st('crit', 'failed');
      if (r.conflicts && r.conflicts.length) res = h('span', null, res, h('div', { 'class': 'small crit' }, 'conflict: ' + r.conflicts.join('; ')));
      var w = r.wrapper;
      return [h('span', { 'class': 'mono small' }, r.window), 'P' + r.phase, r.suite + (r.attempt ? ' #' + r.attempt : ''), res,
        r.passed !== null ? h('span', { 'class': 'num' }, r.passed + ' / ' + r.failed, r.failed ? h('span', { 'class': 'crit' }, ' ✕') : '') : ': ',
        txt(r.pin), txt(r.ended_local),
        w ? 'rc ' + txt(w.command_rc) + ' · ' + txt(w.phase) + ' · ' + txt(w.containment) : 'no wrapper record',
        r.cross_check ? (r.cross_check.agrees === false ? st('warn', 'lines ' + r.cross_check.pass_lines + '/' + r.cross_check.fail_lines + ' differ') :
          r.cross_check.agrees ? st('ok', 'lines agree') : 'no counts in the name') : ': '];
    });
    var bad = (E.folders || []).filter(function (f) { return f.sums !== 'ok'; });
    return card('Acceptance runs', { src: 'From committed evidence at ' + txt(E.source && E.source.commit && E.source.commit.slice(0, 12)) + ': the file name (counts, pin) and the wrapper record are the result; PASS/FAIL line counts are only a cross-check. Failed attempts are kept. The dashboard never re-runs a suite.' },
      [rows.length ? table(['Window', 'Phase', 'Suite', 'Result', 'Pass / fail', 'Pin', 'Ended (local)', 'Wrapper', 'Cross-check'], rows) : h('div', { 'class': 'empty' }, 'No acceptance outputs in the verified evidence.'),
        bad.length ? h('div', { 'class': 'errbar' }, bad.map(function (f) { return h('div', null, st('crit', f.folder + ': ' + f.detail + ' :  nothing from it is shown')); })) : null]);
  }

  /* ---- Scenarios and Replay ------------------------------------------------------------------- */
  var TRUST = { independent: ['t1', 'T1 independent'], 'co-located': ['t2', 'T2 co-located'], 'actor-written': ['t3', 'T3 actor-written'] };
  function trust(t) { var d = TRUST[t] || ['', txt(t)]; return h('span', { 'class': 'trust ' + d[0] }, d[1]); }
  function runsOf() { return S.evidence && S.evidence.scenarios ? S.evidence.scenarios.runs || [] : []; }
  function scenariosTab(r) {
    var E = S.evidence;
    var head = ctx([['Subject', 'agents under test (never the coding sessions)'], ['Sources', 'sacct (controller pod), login-pod sshd, K3s events, journald, lease records, GitLab notes, LOG.md'],
      ['Rule', 'only evidence folders with verified SHA256SUMS, written by the capture tool within about an hour of STOP']]);
    if (!E) return [head, failed('evidence', 'Evidence data')];
    var runs = runsOf(), errs = (E.scenarios && E.scenarios.errors) || [];
    var list = card('Scenario runs', { src: 'The capture tool that writes these folders is its own MR; K3s events expire after about an hour, so it runs right after STOP.' },
      [runs.length ? h('div', { 'class': 'runs' }, runs.map(function (run, i) {
        return h('a', { 'class': 'run', href: '#scenarios/' + i, 'aria-current': i === r.run ? 'true' : null, 'data-key': 'run-' + i },
          h('b', null, txt(run.run_id)), ' · ' + when(run.start) + ' · ' + run.actors.length + ' actor(s) · ' + run.events.length + ' events · ' + run.files.length + ' files'
            + (run.simulation ? ' · local simulation' : run.physical ? ' · physical cluster' : ''),
          run.capture_late ? h('div', null, st('warn', 'captured late: K3s events may be incomplete')) : null);
      })) : h('div', { 'class': 'empty' }, 'No scenario runs recorded yet.'),
      errs.map(function (e) { return h('div', { 'class': 'errbar' }, st('crit', e.folder + ': ' + e.error + ' :  not rendered')); })]);
    var run = runs[r.run];
    return [head, list, run ? runDetail(run, r.run) : null, trustLegend(), viewsCard()];
  }
  /* ---- a simulated security scenario as one chain (8 Oct) ----------------------------------------
     run.simulation is the collector's validated pass-through of the run's capture source and its sanitized,
     verifier-approved summary (C23b). Every step starts MISSING and
     only matching evidence makes it PASS; a verdict the steps do not support is CONTRADICTED. The chain reads
     verified only with the verifier's approval, a committed source, and cluster contact ruled out. Recording can use a declared model; replay cannot. */
  var SIM_STEPS = [
    ['attack', 'Weakness recorded', 'original execution: the declared actions ran against the deliberately weak fixture'],
    ['repair', 'Repair applied', 'an operator step, outside the agent’s tools; it counts only as far as the replay shows it'],
    ['replay', 'Replay after the repair', 'execution replay: the recorded actions executed again, with no model'],
    ['regression', 'Legitimate use still works', 'authorized writers and a normal project job, after the repair'],
    ['reset', 'Fixture reset', 'the seeded fixture restored, then discarded (not a cluster recovery)']
  ];
  var SIM_VERDICT = { attack: ['baseline', 'security_failure'], replay: ['patched', 'security_blocked'], regression: ['functional', 'pass'] };
  var SIM_STATE = { pass: ['ok', 'PASS'], fail: ['crit', 'FAIL'], missing: ['unk', 'MISSING'], contradicted: ['crit', 'CONTRADICTED'] };
  function simChain(sim) {
    var ev = Array.isArray(sim.events) ? sim.events.filter(function (e) { return e && typeof e === 'object'; }) : [];
    function of(phase, type) { return ev.filter(function (e) { return e.phase === phase && e.event_type === type; }); }
    var steps = {}, reasons = [];
    ['attack', 'replay', 'regression', 'reset'].forEach(function (phase) {
      var obs = of(phase, 'observation');
      steps[phase] = { obs: obs, acts: of(phase, 'action'),
        state: !obs.length ? 'missing' : obs.every(function (o) { return o.status === 'pass'; }) ? 'pass' : 'fail' };
    });
    var expected = sim.scenario_kind === 'read' ? {
      actions: ['find-readable-canary', 'read-synthetic-canary'], attack: ['vulnerable-canary-read'], replay: ['patched-read-blocked']
    } : { actions: ['find-writable-target', 'write-synthetic-marker'], attack: ['vulnerable-marker-present'], replay: ['patched-write-blocked'] };
    expected.regression = ['alpha-authorized-write', 'beta-authorized-write', 'normal-project-job'];
    expected.reset = ['metadata-reset'];
    ['attack', 'replay', 'regression', 'reset'].forEach(function (phase) {
      var ids = steps[phase].obs.map(function (e) { return e.id; });
      if (steps[phase].state === 'pass' && (ids.length !== expected[phase].length || expected[phase].some(function (id) { return ids.indexOf(id) < 0; }))) {
        steps[phase].state = 'missing';
      }
    });
    if (steps.attack.state === 'pass' && (!steps.attack.acts.length || steps.attack.acts.some(function (a) { return a.status !== 'ok'; }))) steps.attack.state = 'fail';
    var rec = steps.attack.acts.map(function (a) { return a.id; }), rep = steps.replay.acts.map(function (a) { return a.id; });
    if (rec.length && (rec.length !== expected.actions.length || rec.some(function (id, i) { return id !== expected.actions[i]; }))) {
      steps.attack.state = 'contradicted'; reasons.push('the original actions do not match this scenario');
    }
    if (steps.replay.state === 'pass' && rep.length && (steps.replay.acts[rep.length - 1].status !== 'denied' ||
        steps.replay.acts.slice(0, -1).some(function (a) { return a.status !== 'ok'; }))) {
      steps.replay.state = 'fail'; reasons.push('the replay has no final authorization denial');
    }
    if (!rep.length) { if (steps.replay.state === 'pass') steps.replay.state = 'missing'; }
    else if (rep.length > rec.length || rep.some(function (id, i) { return id !== rec[i]; })) {
      steps.replay.state = 'contradicted';
      reasons.push('the replayed actions are not the recorded ones, in order');
    }
    if (steps.reset.state === 'pass' && (sim.cleanup !== 'complete' || sim.fixture_discarded !== true)) {
      steps.reset.state = 'fail';
      reasons.push('cleanup is ' + txt(sim.cleanup, 'not recorded') + '; fixture discarded: ' + txt(sim.fixture_discarded));
    }
    var v = sim.verdicts && typeof sim.verdicts === 'object' ? sim.verdicts : {};
    Object.keys(SIM_VERDICT).forEach(function (phase) {
      var key = SIM_VERDICT[phase][0], says = v[key] === SIM_VERDICT[phase][1], shows = steps[phase].state === 'pass';
      if (says !== shows) {
        if (shows) steps[phase].state = 'contradicted';
        reasons.push('verdict ' + key + ' is ' + txt(v[key], 'missing') + ' but the evidence shows ' + SIM_STATE[steps[phase].state][1]);
      }
    });
    // the repair has no record of its own: it is effective exactly as far as the replay, once checked, shows
    steps.repair = { obs: [], acts: [], state: steps.replay.state === 'pass' ? 'pass' : steps.replay.state === 'missing' ? 'missing' : 'fail' };
    SIM_STEPS.forEach(function (s) {
      if (steps[s[0]].state !== 'pass') reasons.push(s[1] + ': ' + SIM_STATE[steps[s[0]].state][1]);
    });
    if (sim.verified !== true) reasons.push('the verifier did not approve this export');
    if (sim.source_dirty !== false) reasons.push(sim.source_dirty ? 'built from an uncommitted source' : 'source state not recorded');
    if (typeof sim.model_used !== 'boolean' || (sim.model_used && !sim.model)) reasons.push('model provenance is not recorded');
    if (sim.fleet_contacted !== false) reasons.push('cluster contact is not ruled out, so this cannot read as a local simulation');
    return { steps: steps, verified: !reasons.length, reasons: reasons, recorded: rec.length, replayed: rep.length };
  }
  function simCard(run) {
    var sim = run.simulation, c = simChain(sim);
    function item(e) { return h('li', { 'class': 'small' }, h('span', { 'class': 'mono' }, txt(e.id)), ' · ' + txt(e.status)); }
    var steps = h('ol', { 'class': 'simsteps' }, SIM_STEPS.map(function (s) {
      var x = c.steps[s[0]], d = SIM_STATE[x.state];
      return h('li', { 'class': 'simstep', 'data-key': 'sim-' + s[0] }, h('div', null, st(d[0], d[1], true), ' ', h('b', null, s[1])),
        h('div', { 'class': 'small muted' }, s[2]),
        x.acts.length || x.obs.length ? h('ul', { 'class': 'simev' }, x.acts.map(item), x.obs.map(item)) : null);
    }));
    var kinds = h('div', { 'class': 'simkinds' },
      row('Original execution', c.recorded + ' declared action(s), run once against the weak fixture'),
      row('Execution replay', c.replayed + ' of them executed again after the repair' + (sim.driver === 'nemo' ? ', stepped by NeMo' : '') + ', no model'),
      row('Browser playback', 'this page and Replay step through saved evidence; they execute nothing'));
    return card('Simulated security scenario', {
      badge: c.verified ? st('ok', 'Chain verified · local simulation', true) : st('warn', 'Not verified', true),
      src: 'From the run’s sanitized, verifier-approved summary; the raw proofs stay in the private bundle.' }, [
      h('p', { 'class': 'simscope' }, h('b', null, 'Local Linux ACL simulation. '),
        'The Linux kernel decided each read and write, made as each numeric identity on a disposable fixture. Slurm accounting and quota are stand-ins. ' + (sim.fleet_contacted === false ? 'No cluster node was contacted. ' : 'Cluster contact is not ruled out. ') + (sim.model_used === false ? 'No model was used.' : sim.model_used === true ? 'Recording used model ' + txt(sim.model) + '; replay used no model.' : 'Model use is not recorded.')),
      ctx([['Proof scope', sim.proof_scope && typeof sim.proof_scope === 'object' ? Object.keys(sim.proof_scope).map(function (k) { return k + ': ' + sim.proof_scope[k]; }).join('; ') : txt(sim.proof_scope)], ['Reset scope', txt(sim.reset_scope)],
        ['Source', txt(sim.source_revision && String(sim.source_revision).slice(0, 12)) + (sim.source_dirty === false ? '' : ' (not clean)')],
        ['Driver', txt(sim.driver) + (sim.framework_version ? ' ' + sim.framework_version : '')]]),
      steps, kinds,
      c.reasons.length ? h('ul', { 'class': 'simwhy small' }, c.reasons.map(function (r) { return h('li', null, r); })) : null]);
  }
  function physicalCard(run) {
    var p = run.physical, expected = p.scenario_kind === 'read'
      ? ['find-readable-canary', 'read-synthetic-canary'] : ['find-writable-target', 'write-synthetic-marker'];
    var actions = Array.isArray(p.actions) ? p.actions : [];
    var provenance = p.schema === 'prace.physical-recording-public.v1' && p.verified === true &&
      p.scope === 'physical-permission-fixture' && p.source_dirty === false &&
      /^[0-9a-f]{40}$/.test(p.source_revision || '') && p.driver === 'nemo' &&
      typeof p.model === 'string' && p.model.length > 0 && typeof p.framework_version === 'string' && p.framework_version.length > 0 &&
      Number.isInteger(p.model_calls) && p.model_calls > 0 &&
      ['journal_tip_sha256', 'manifest_sha256', 'objective_sha256'].every(function (k) { return /^[0-9a-f]{64}$/.test(p[k] || ''); });
    var recording = provenance && ['read', 'write'].indexOf(p.scenario_kind) >= 0 && p.recording === true &&
      actions.length === expected.length && actions.every(function (a, i) { return a && a.id === expected[i] && a.status === 'ok'; });
    var objective = recording && p.objective === true;
    function step(name, state, note) {
      return h('li', { 'class': 'simstep' }, h('div', null, st(state === 'PASS' ? 'ok' : state === 'FAIL' ? 'crit' : 'unk', state, true), ' ', h('b', null, name)),
        h('div', { 'class': 'small muted' }, note));
    }
    return card('Physical security scenario · recording only', {
      badge: st(objective ? 'ok' : 'warn', objective ? 'Recording and objective verified · T2' : 'Not verified', true),
      src: 'Collector recomputed the journal and source bindings. Co-located proofs; no T1 independence.' }, [
      h('p', { 'class': 'simscope' }, 'Physical synthetic permission fixture with declared discovery and exact read/write actions. Browser playback executes nothing.'),
      ctx([['Source', txt(p.source_revision && String(p.source_revision).slice(0, 12))],
        ['Model', txt(p.model)], ['Driver', txt(p.driver) + ' ' + txt(p.framework_version)],
        ['Model calls', txt(p.model_calls) + ' (driver report, T3)']]),
      h('ol', { 'class': 'simsteps' }, [
        step('Recording', recording ? 'PASS' : 'NOT VERIFIED', 'Declared actions and original gateway records agree.'),
        step('Objective', objective ? 'PASS' : recording && p.objective === false ? 'FAIL' : 'NOT VERIFIED', 'Separate co-located observer facts match the recorded action.'),
        step('Repair', 'NOT RUN', 'No verified follow-up is attached to this recording.'),
        step('Replay', 'NOT RUN', 'No execution replay is proved by browser playback.'),
        step('Legitimate use', 'NOT RUN', 'No post-repair regression is attached.'),
        step('Reset', p.reset_pending === true ? 'PENDING' : 'NOT VERIFIED', 'State at recording STOP; full-cluster restoration is unqualified.')]),
      h('p', { 'class': 'small muted' }, 'Historical recording snapshot. Later scoped cleanup and the current lease state are outside this journal.')]);
  }
  function runDetail(run, idx) {
    var t0 = run.start, t1 = Math.max(run.stop, t0 + 1);
    var sel = S.sel.run === idx && S.sel.ev !== null ? run.events[S.sel.ev] : null;
    function pick(i) { return function () { S.sel.run = idx; S.sel.ev = i; render(); }; }
    var lanes = h('div', { 'class': 'lanes', role: 'group', 'aria-label': 'Timeline' }, [['actors', 'Actors under test'], ['fleet', 'Fleet'], ['ctx', 'Operator context']].map(function (ln) {
      return h('div', { 'class': 'lane' }, h('span', { 'class': 'small muted' }, ln[1]), h('div', { 'class': 'track' },
        run.events.map(function (e, i) {
          if (e.lane !== ln[0]) return null;
          var pos = Math.min(100, Math.max(0, (e.t - t0) / (t1 - t0) * 100));
          return h('button', { 'class': 'ev k-' + e.kind + (e.trust === 'co-located' ? ' t2' : e.trust === 'actor-written' ? ' t3' : ''), type: 'button', left: pos + '%', 'data-key': 'ev-' + i,
            title: when(e.t) + ' · ' + e.title + ' · ' + (TRUST[e.trust] || [0, e.trust])[1], 'aria-pressed': sel === e ? 'true' : 'false', onclick: pick(i) },
          h('span', { 'class': 'sr' }, e.title));
        })));
    }));
    var list = h('div', { 'class': 'evlist' }, run.events.map(function (e, i) {
      return h('button', { type: 'button', onclick: pick(i), 'data-key': 'evl-' + i }, when(e.t) + ' · ' + e.lane + ' · ' + e.title + ' ', trust(e.trust));
    }));
    var detail = sel ? h('div', { 'class': 'detail' },
      h('div', null, h('div', { 'class': 'k' }, when(sel.t)), h('b', null, sel.title), row('Actor', txt(sel.actor)), row('Host', txt(sel.host)), row('Source', sel.src.join(' + ')),
        h('div', null, trust(sel.trust), ' ', h('span', { 'class': 'small muted' }, sel.why)),
        sel.trust_parts ? h('ul', { 'class': 'small' }, sel.trust_parts.map(function (p) { return h('li', null, p.src + ': ', trust(p.trust)); })) : null),
      h('div', null, h('div', { 'class': 'k' }, 'Record'), h('div', { 'class': 'mono small' }, txt(sel.text)), h('div', { 'class': 'small muted' }, 'evidence: ' + txt(sel.ev))),
      h('div', null, h('div', { 'class': 'k' }, 'Correlates with'), correlated(run, sel).map(function (e) { return h('div', { 'class': 'small' }, when(e.t) + ' · ' + e.title + ' ', trust(e.trust)); }),
        sel.actor ? h('p', null, h('a', { href: '#replay/' + idx + '/' + encodeURIComponent(sel.actor) }, 'Open ' + sel.actor + ' in Replay')) : null))
      : h('p', { 'class': 'small muted' }, 'Select an event to see its record, source and trust.');
    var actors = run.actors.map(function (a) { return h('span', { 'class': 'chip' }, a.name + (a.under_test ? ' · under test' : ' · background')); });
    var screens = (run.terminal || []).length ? h('div', { 'class': 'screens' }, h('span', { 'class': 'small muted' }, 'Terminal playback (', trust('actor-written'), '): '),
      run.terminal.map(function (x) {
        return x.withheld ? h('span', { 'class': 'chip' }, st('warn', x.name + ' withheld: ' + x.withheld))
          : h('a', { 'class': 'chip', href: '#play/' + run.run_id + '/' + x.name, 'data-key': 'play-' + x.name }, '▶ ' + playLabel(x.name) + ' · ' + dur(x.duration));
      })) : null;
    return [run.physical && typeof run.physical === 'object' ? physicalCard(run) : run.simulation && typeof run.simulation === 'object' ? simCard(run) : null,
      card(txt(run.run_id) + (run.title ? ' · ' + run.title : ''), { src: 'Folder ' + run.folder + ' · START ' + when(run.start) + ' · STOP ' + when(run.stop) + ' · captured ' + (run.captured_at ? age(run.captured_at - run.stop) + ' after STOP' : 'time not recorded') },
      [h('div', { 'class': 'jobs' }, actors), screens, lanes, list, detail,
        run.recovery ? h('p', { 'class': 'small' }, 'Recovery points: before ' + txt(run.recovery.before) + ' · after ' + txt(run.recovery.after) + ' · restore test ' + txt(run.recovery.restore_test, 'not recorded')) : null]),
      card('Evidence for this run', { badge: st('ok', 'SHA256SUMS verified', true), src: 'Read from the run folder only; the capture tool is a separate MR, and the K3s events are the part that expires.' },
        table(['File', 'sha256', 'About'], run.files.map(function (f) { return [h('span', { 'class': 'mono' }, f.name), h('span', { 'class': 'mono' }, txt(f.sha256)), txt(f.about)]; })))];
  }
  function correlated(run, e) {
    return run.events.filter(function (x) { return x !== e && x.lane === 'fleet' && Math.abs(x.t - e.t) <= 120; });
  }
  function trustLegend() {
    return card('Source trust', { src: 'Assigned by the evidence builder from a fixed table (trust-table.json), never from the record itself. A finding stands on T1; T2 corroborates; T3 is context.' },
      [row(trust('independent'), 'recorded where the actor never had a session or job: controller-pod sacct, the observer, the monitor, GitLab, LOG.md, the lease file, recovery points'),
        row(trust('co-located'), 'recorded where the actor had a session or job, or beside the agent: login-pod sshd, a worker’s journald or K3s events, the harness gateway, tracer and validator (dashed ring)'),
        row(trust('actor-written'), 'written by the actor: job output, files under /home, the agent’s own trace (dotted ring)')]);
  }
  function viewsCard() {
    return card('Two views, two places', { src: 'Transcripts of the coding sessions are never read or bundled.' },
      table(['', 'Workstation (private)', 'mgmt-git01 (scrubbed)'], [
        ['Hostnames', 'real', 'roles (login-node, cpu-worker-1, gpu-worker-1–3)'], ['Accounts', 'real', 'letters (actor-A, agent-A, member-1)'],
        ['Addresses, MAC, PCI', 'real', 'masked'], ['Lease and point ids', 'real', 'masked'], ['Pod names', 'real', 'hash suffix masked']]));
  }
  function replayTab(r) {
    var run = runsOf()[r.run];
    if (!run) return [h('p', null, h('a', { href: '#scenarios' }, '← Scenarios')), h('div', { 'class': 'empty' }, 'No such run.')];
    var steps = run.events.filter(function (e) { return e.actor === r.actor; });
    var i = Math.min(S.sel.step, Math.max(0, steps.length - 1));
    var cur = steps[i];
    function go(n) { return function () { S.sel.step = n; render(); }; }
    var obs = cur ? nearest(run.observations, cur.t) : null;
    return [h('p', null, h('a', { href: '#scenarios/' + r.run }, '← ' + txt(run.run_id)), ' · Replay of ', h('b', null, r.actor), ' · ' + steps.length + ' steps'),
      steps.length ? h('div', { 'class': 'replay' },
        h('div', { 'class': 'steps', role: 'list' }, steps.map(function (e, n) {
          return h('button', { type: 'button', role: 'listitem', 'aria-current': n === i ? 'step' : null, onclick: go(n), 'data-key': 'step-' + n }, when(e.t) + ' · ' + e.title + ' · ' + e.src.join('+') + ' · ' + txt(e.host) + ' ', trust(e.trust));
        })),
        card('Step ' + (i + 1) + ' of ' + steps.length, { src: 'Replay reads the bundle only; it never re-queries sacct, sshd or K3s. Sources keep their own clocks (tolerance about ±5 s); nothing is reordered to tidy the story.' },
          [h('div', { 'class': 'outcome' }, when(cur.t)), h('div', { 'class': 'small muted' }, '+' + age(cur.t - run.start) + ' from START'),
            h('h3', null, cur.title), trust(cur.trust), h('span', { 'class': 'small muted' }, ' ' + cur.why),
            h('div', { 'class': 'mono small' }, txt(cur.text)), h('div', { 'class': 'small muted' }, 'evidence: ' + txt(cur.ev) + ' · host ' + txt(cur.host)),
            h('h3', null, 'Fleet at this moment'), obs ? fleetAt(obs, cur.host) : h('p', { 'class': 'muted' }, 'No observation in this run folder.'),
            h('h3', null, 'Fleet events within ±2 min'), correlated(run, cur).map(function (e) { return h('div', { 'class': 'small' }, when(e.t) + ' · ' + e.title + ' ', trust(e.trust)); }),
            h('div', { 'class': 'pager' }, h('button', { type: 'button', disabled: i === 0, onclick: go(i - 1), 'data-key': 'prev' }, 'Previous'),
              h('button', { type: 'button', disabled: i >= steps.length - 1, onclick: go(i + 1), 'data-key': 'next' }, 'Next'))]))
        : h('div', { 'class': 'empty' }, 'No steps for this actor.')];
  }
  /* ---- Terminal playback (8 Oct): a terminal-session run's screens, from its verified evidence folder.
     The builder publishes complete logical lines ([settled, row, began, text, rows]); typing between the
     first and last change is interpolated here. This is a scrubbed transcript, not a desktop video. Nothing runs. */
  var SPEEDS = [1, 2, 4, 8];
  S.play = { key: '', t: 0, playing: false, speed: 1, wall: 0 };
  function playLabel(name) { return name === 'original' ? 'the recorded session' : name === 'replay' ? 'its replay on the cluster' : name; }
  function screenAt(term, T) {
    var cur = {};
    term.lines.forEach(function (e) { if (e[0] <= T) cur[e[1]] = [e[3], e[4]]; });
    term.lines.forEach(function (e) {   /* a line still being typed: from its last published text towards the next */
      if (e[2] <= T && T < e[0] && e[0] > e[2]) {
        var prev = cur[e[1]] ? cur[e[1]][0] : '', next = e[3];
        if (next.indexOf(prev) !== 0) return;
        if (!prev) { var p = next.indexOf('$ '); if (p >= 0 && p < 120) prev = next.slice(0, p + 2); }   /* the prompt is printed, not typed */
        var k = Math.ceil((T - e[2]) / (e[0] - e[2]) * (next.length - prev.length));
        cur[e[1]] = [next.slice(0, prev.length + Math.max(0, k)), e[4]];
      }
    });
    var out = [], want = null;
    Object.keys(cur).map(Number).sort(function (a, b) { return a - b; }).forEach(function (s) {
      if (want !== null) for (var i = want; i < s; i++) out.push('');   /* blank lines were never written */
      out.push(cur[s][0]); want = s + Math.max(1, cur[s][1]);
    });
    return out;
  }
  function clock(sec) { sec = Math.max(0, Math.floor(sec)); return Math.floor(sec / 60) + ':' + ('0' + sec % 60).slice(-2); }
  function playRun(r) { return runsOf().find(function (run) { return run.run_id === r.runId; }); }
  function playState(r, term) {
    var key = r.runId + '/' + r.name;
    if (S.play.key !== key) S.play = { key: key, t: 0, playing: false, speed: S.play.speed || 1, wall: 0 };
    S.play.t = Math.min(S.play.t, term.duration);
    return S.play;
  }
  function paintTerm() {   /* the screen and clock only, in place, so playback never rebuilds the page */
    var box = document.querySelectorAll('[data-term]')[0], tm = document.querySelectorAll('[data-term-time]')[0];
    var r = route(), run = playRun(r), term = run && (run.terminal || []).find(function (x) { return x.name === r.name && x.lines; });
    if (!box || !term) return;
    var lines = screenAt(term, S.play.t);
    box.replaceChildren ? box.replaceChildren() : (function () { while (box.firstChild) box.removeChild(box.firstChild); })();
    lines.forEach(function (l) { box.appendChild(h('div', { 'class': 'tl' }, l || ' ')); });
    try { box.scrollTop = box.scrollHeight; } catch (e) { /* not every view scrolls */ }
    if (tm) tm.textContent = clock(S.play.t) + ' / ' + clock(term.duration) + (term.start ? ' · ' + when(term.start + S.play.t) : '');
  }
  function playTick() {
    var P = S.play;
    if (!P.playing) return;
    var r = route(), run = playRun(r), term = run && (run.terminal || []).find(function (x) { return x.name === r.name && x.lines; });
    if (r.tab !== 'play' || !term) { P.playing = false; return; }
    var now = Date.now();
    P.t += Math.max(0, now - P.wall) / 1000 * P.speed; P.wall = now;
    if (P.t >= term.duration) { P.t = term.duration; P.playing = false; render(); return; }
    paintTerm();
  }
  function playTab(r) {
    var run = playRun(r);
    var back = h('p', null, h('a', { href: run ? '#scenarios/' + runsOf().indexOf(run) : '#scenarios' }, '← ' + (run ? txt(run.run_id) : 'Scenarios')));
    var term = run && (run.terminal || []).find(function (x) { return x.name === r.name; });
    if (!run || !term) return [back, h('div', { 'class': 'empty' }, 'No such recorded screen.')];
    if (term.withheld) return [back, h('div', { 'class': 'errbar' }, st('warn', term.name + ' withheld: ' + term.withheld))];
    var P = playState(r, term);
    function act(f) { return function () { f(); P.wall = Date.now(); render(); }; }
    var others = run.terminal.map(function (x) {
      return h('a', { 'class': 'chip', href: '#play/' + r.runId + '/' + x.name, 'aria-current': x.name === r.name ? 'page' : null, 'data-key': 'screen-' + x.name }, playLabel(x.name));
    });
    var note = r.name === 'replay'
      ? 'The commands this screen shows were rebuilt from the recorded session’s keystrokes and run again on the cluster as the same user, with new job IDs. That proves the commands and their accounting, not a restored environment or identical output files.'
      : 'A transcript reconstructed from the user’s terminal recording. Only the final version of each line is shown; typing is interpolated. This is not the original desktop video or an exact replay of screen changes.';
    var box = h('div', { 'class': 'term', 'data-term': '1', role: 'log', 'aria-label': 'Recorded terminal', tabindex: 0 });
    var view = [back,
      card('Playback · ' + txt(run.run_id) + ' · ' + playLabel(r.name), { badge: trust('actor-written'),
        src: 'Played in this browser from the run’s verified evidence folder (' + term.file + '), scrubbed like the rest of this page. Playback executes nothing; job IDs and times are as recorded. Controller accounting (T1) for these jobs is on the run’s timeline.' },
        [h('div', { 'class': 'jobs' }, others),
          h('p', { 'class': 'small muted' }, note),
          h('div', { 'class': 'pager' },
            h('button', { type: 'button', onclick: act(function () { if (P.t >= term.duration) P.t = 0; P.playing = !P.playing; }), 'data-key': 'play-toggle' }, P.playing ? 'Pause' : 'Play'),
            h('button', { type: 'button', onclick: act(function () { P.t = 0; P.playing = false; }), 'data-key': 'play-restart' }, 'Restart'),
            h('button', { type: 'button', onclick: act(function () { P.t = term.duration; P.playing = false; }), 'data-key': 'play-end' }, 'End'),
            SPEEDS.map(function (s) {
              return h('button', { type: 'button', 'aria-pressed': P.speed === s ? 'true' : 'false', onclick: act(function () { P.speed = s; }), 'data-key': 'play-speed-' + s }, s + '×');
            }),
            h('span', { 'class': 'mono small', 'data-term-time': '1' }, '')),
          box])];
    return view;
  }
  function nearest(list, t) {
    var best = null;
    (list || []).forEach(function (o) { if (!best || Math.abs(o.t - t) < Math.abs(best.t - t)) best = o; });
    return best;
  }
  function fleetAt(o, host) {
    var hrow = (o.hosts || {})[host];
    return [row('Observation', when(o.t) + ' (' + o.file + ')'), row('Lease', o.lease_held ? 'held' : 'not held'),
      row('Host ' + txt(host), !hrow ? 'not in this observation' : 'Kubernetes ' + (hrow.k8s_ready ? 'Ready' : 'not Ready') + ' \u00b7 slurmd pod ' +
        (hrow.slurmd_pod_ready === null || hrow.slurmd_pod_ready === undefined ? 'none' : hrow.slurmd_pod_ready ? 'Ready' : 'not Ready') + ' \u00b7 ' + txt(hrow.slurm_state)),
      row('Partitions', o.partitions ? Object.keys(o.partitions).map(function (k) { return k + ' ' + o.partitions[k]; }).join(', ') : 'not observed'),
      row('Share-mount observations', txt(o.share_pods))];
  }

  /* ---- CI/CD ---------------------------------------------------------------------------------- */
  function pipeLink(G, id) {
    return /^[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+$/.test(G.project || '') && typeof id === 'number'
      ? h('a', { href: '/' + G.project + '/-/pipelines/' + id }, '#' + id) : '#' + txt(id);
  }
  function tokenRow(label, t) {
    if (!t) return row(label, 'unknown');
    if (t.error) return row(label, st('crit', t.error), true);
    var left = t.days_left;
    return row(label, h('span', null, t.warn ? st('warn', left === null || left === undefined ? 'expiry unknown' : 'expires in ' + left + ' d') : st('ok', 'expires in ' + left + ' d'),
      ' · ' + txt(t.expires_at, 'no date') + (t.scopes ? ' · scopes ' + t.scopes.join(',') : '') + (t.broader_than_read_api ? ' (broader than read_api!)' : ''), h('span', { 'class': 'small muted' }, ' · ' + t.source)), t.warn);
  }
  function cicdTab() {
    var G = S.gitlab;
    var head = ctx([['Source', 'GitLab REST v4 on mgmt-git01, the dashboard’s own read-only token (0600 file), every 5 min'], ['Project', G ? G.project : 'hpcc/prace-hackathon'], ['Note', 'GitHub is a scrubbed export, not a source']]);
    if (!G) return [head, failed('gitlab', 'GitLab data')];
    if (G.error) return [head, h('div', { 'class': 'errbar' }, st('crit', G.error)), card('Tokens', {}, [tokenRow('Monitor token', G.monitor_token)])];
    var gage = serverNow() - G.generated_at;
    var mr = G.merge_requests || {};
    var lm = mr.last_merged;
    var freeze = card('Main', { stale: gage > GL_AMBER, badge: gage > GL_AMBER ? st('stale', 'GitLab data ' + age(gage) + ' old', true) : null,
      src: 'The freeze is an owner-set flag on mgmt-git01 (/etc/prace-dash/freeze.json); there is no machine-readable freeze in the repository. Reviews are by a session other than the author, recorded in MR notes.' },
      [row('Freeze', h('span', null, G.freeze.state === 'frozen' ? st('def', 'frozen') : G.freeze.state === 'open' ? st('ok', 'open') : st('unk', 'unknown'), G.freeze.note ? ' · ' + G.freeze.note : '')),
        mr.error ? row('Merge requests', st('crit', mr.error), true) : [
          row('Last merge', lm ? '!' + lm.iid + ' ' + lm.title + ' · ' + when(lm.merged) + ' · ' + (lm.approvals ? lm.approvals + ' approval(s)' : 'reviewer: see MR notes') : 'none'),
          row('Open MRs', (mr.open || []).length + (mr.open_capped ? '+' : ''))],
        tokenRow('Dashboard token', G.token), tokenRow('Monitor token', G.monitor_token)]);
    var P = G.pipelines || {};
    var pipes = card('Pipelines per branch', { src: 'Latest 20 pipelines; jobs shown for the newest pipeline of each of up to 6 refs.' },
      P.error ? h('div', { 'class': 'errbar' }, st('crit', P.error)) : table(['Ref', 'Pipeline', 'Status', 'Wall time', 'Source', 'Jobs'], (P.items || []).map(function (p) {
        return [h('span', { 'class': 'mono' }, p.ref), pipeLink(G, p.id), st(JOB[p.status] || 'unk', p.status), dur(p.wall_s), p.source,
          p.jobs ? h('div', { 'class': 'jobs' }, p.jobs.map(function (j) { return h('span', { 'class': 'chip', title: j.stage }, st(JOB[j.status] || 'unk', j.name + ' ' + dur(j.duration))); })) : ''];
      })));
    var main = (P.items || []).find(function (p) { return p.id === P.latest_main; });
    var maxd = main && main.jobs ? Math.max.apply(null, main.jobs.map(function (j) { return j.duration || 0; }).concat([1])) : 1;
    var bars = card('Job durations, latest main pipeline', {},
      main && main.jobs ? h('div', { 'class': 'bars' }, main.jobs.map(function (j) {
        return h('div', { 'class': 'bar' }, h('span', { 'class': 'mono small' }, j.name), h('div', { 'class': 'track' }, h('div', { 'class': 'fillbar', width: ((j.duration || 0) / maxd * 85) + '%' }), h('span', { 'class': 'lab', left: ((j.duration || 0) / maxd * 85) + '%' }, dur(j.duration))));
      })) : h('div', { 'class': 'empty' }, 'No main pipeline in the latest 20.'));
    var D = G.drift_audit || {};
    var drift = card('Scheduled drift audit (' + txt(D.job, 'lab-drift-check') + ')', { src: 'The only place configuration drift is detected: the scheduled CI job’s full evaluation (audit/result.json in its artifacts). It feeds the banner’s drift line.' },
      D.error ? h('div', { 'class': 'errbar' }, st('crit', D.error)) : (D.items || []).length ? h('div', { 'class': 'squares' }, D.items.map(function (i) {
        return h('div', { 'class': 'sq', title: (i.reasons || []).join('; ') }, i.outcome ? outcome(i.outcome, false) : st(JOB[i.job_status] || 'unk', txt(i.job_status, 'no job')), h('div', null, when(i.created).slice(0, 10)), pipeLink(G, i.pipeline));
      })) : h('div', { 'class': 'empty' }, 'No scheduled pipeline found.'));
    var MI = G.monitor_issues || {};
    var issues = card('Fleet-monitor issues', { src: 'Issues labelled ' + txt((MI.labels || []).join(',')) + '. These are confidential, so only the outcome word of the title is shown. Never configuration drift.' },
      MI.error ? h('div', { 'class': 'errbar' }, st('crit', MI.error)) : (MI.items || []).length ? table(['Issue', 'Outcome', 'State', 'Opened', 'Closed', 'Open for'], MI.items.map(function (i) {
        return ['#' + i.iid, i.outcome ? outcome(i.outcome, true) : txt(i.outcome, 'monitor failure'), i.state, when(i.created), i.closed ? when(i.closed) : ': ', age((i.closed || serverNow()) - i.created)];
      })) : h('div', { 'class': 'empty' }, 'No fleet-monitor issue.'));
    var L = S.latest, pins = L && L.static && L.static.pins;
    var pinCard = card('Pinned images and package snapshot', { src: 'From the repository at deploy time (role defaults), not from the fleet. Driver and CUDA are static inventory.' },
      pins && pins.length ? table(['Component', 'Pinned', 'Digest'], pins.map(function (p) { return [h('span', { 'class': 'mono' }, p.name), h('span', { 'class': 'mono' }, txt(p.version)), h('span', { 'class': 'mono small' }, p.digest ? p.digest.slice(0, 19) + '…' : ': ')]; }))
        : h('div', { 'class': 'empty' }, 'No pin table in this build.'));
    var cve = card('CVE matching', { prov: 'later', src: 'Deferred: the offline package repository carries no advisory metadata (no updateinfo.xml), so matching is not an offline join.' }, h('p', { 'class': 'muted' }, 'Not collected.'));
    return [head, freeze, pipes, h('div', { 'class': 'grid2' }, bars, drift), issues, h('div', { 'class': 'grid2' }, pinCard, cve)];
  }

  /* ---- render loop ---------------------------------------------------------------------------- */
  var lastRoute = '';
  function render() {
    var app = document.getElementById('app');
    var focusKey = document.activeElement && document.activeElement.getAttribute ? document.activeElement.getAttribute('data-key') : null;
    var r = route();
    if (location.hash !== lastRoute) { lastRoute = location.hash; if (r.tab === 'replay') S.sel.step = 0; }
    var body = r.tab === 'slurm' ? slurmTab() : r.tab === 'scenarios' ? scenariosTab(r) : r.tab === 'cicd' ? cicdTab() : r.tab === 'replay' ? replayTab(r)
      : r.tab === 'play' ? playTab(r) : clusterTab();
    var main = h('main', { id: 'main' }, body, footer());
    app.replaceChildren ? app.replaceChildren(header(r), main) : (function () { while (app.firstChild) app.removeChild(app.firstChild); app.appendChild(header(r)); app.appendChild(main); })();
    app.hidden = false;
    if (focusKey) { var f = app.querySelector('[data-key="' + focusKey.replace(/[^A-Za-z0-9-]/g, '') + '"]'); if (f) f.focus(); }
    document.title = 'HPCC-PRACE fleet dashboard · ' + (r.tab === 'cicd' ? 'CI/CD' : r.tab === 'play' ? 'Playback' : r.tab.charAt(0).toUpperCase() + r.tab.slice(1));
    S.fresh = freshness();
    if (r.tab === 'play') paintTerm();
  }
  function load(name) {
    return fetch('data/' + name + '.json', { cache: 'no-cache', credentials: 'same-origin' }).then(function (resp) {
      if (!resp.ok) throw new Error('HTTP ' + resp.status);
      var date = Date.parse(resp.headers.get('Date') || '');
      if (!isNaN(date)) S.skew = Date.now() - date;
      return resp.json();
    }).then(function (doc) {
      if (!doc || doc.schema !== 1) throw new Error('unexpected document');
      var changed = !S[name] || S[name].generated_at !== doc.generated_at || !!S.err[name];
      S[name] = doc; S.err[name] = null; S.got[name] = Date.now();
      return changed;
    }).catch(function (e) {
      var msg = String((e && e.message) || e).slice(0, 200), changed = S.err[name] !== msg;
      S.err[name] = msg;
      return changed;
    }).then(function (changed) { if (changed) render(); else tick(); });
  }
  function start() {
    applyTheme();
    window.addEventListener('hashchange', function () { S.sel.ev = null; render(); window.scrollTo(0, 0); });
    Object.keys(FILES).forEach(function (n) { load(n); setInterval(function () { load(n); }, FILES[n]); });
    setInterval(tick, 15000);   /* ages keep moving between fetches */
    setInterval(playTick, 100);   /* terminal playback, only while playing */
    render();
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start); else start();
})();
