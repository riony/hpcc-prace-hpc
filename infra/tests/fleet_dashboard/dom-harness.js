// DOM-level render harness for roles/fleet_dashboard/files/www/app.js (no browser, no network).
// A minimal DOM: enough for app.js, strict where it matters (innerHTML or an on* attribute throws).
// Usage: node dom-harness.js <www dir> <now epoch> [<advance seconds> <start route>] ; prints one JSON
// report on stdout. With an advance, the page opens on <start route>, the clock moves on by that many
// seconds with the data files unchanged, every interval timer fires once, and the report has
// "clock": the page before and after (review R1: time alone must make data stale).
'use strict';
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const [www, nowArg] = process.argv.slice(2);
const NOW = Number(nowArg);
const ADVANCE = Number(process.argv[4] || 0), START = process.argv[5] || '#cluster';
let clock = NOW;
const timers = [];
let refreshedEvidence = null;
class ClockDate extends Date {
  constructor(...args) { super(...(args.length ? args : [clock * 1000])); }
  static now() { return clock * 1000; }
}

class N {
  constructor() { this.childNodes = []; this.parentNode = null; }
  appendChild(c) { if (c.parentNode) c.parentNode.removeChild(c); c.parentNode = this; this.childNodes.push(c); return c; }
  removeChild(c) { const i = this.childNodes.indexOf(c); if (i >= 0) this.childNodes.splice(i, 1); c.parentNode = null; return c; }
  get firstChild() { return this.childNodes[0] || null; }
  replaceChildren(...kids) { this.childNodes.forEach((c) => { c.parentNode = null; }); this.childNodes = []; kids.forEach((c) => this.appendChild(c)); }
}
class TextNode extends N {
  constructor(t) { super(); this.data = String(t); this.nodeType = 3; }
  get textContent() { return this.data; }
}
class El extends N {
  constructor(tag) { super(); this.tagName = String(tag).toUpperCase(); this.attrs = {}; this.style = {}; this.listeners = {}; this.nodeType = 1; }
  set className(v) { this.attrs.class = String(v); }
  get className() { return this.attrs.class || ''; }
  setAttribute(k, v) { if (/^on/i.test(k) || k === 'style') throw new Error('forbidden attribute ' + k); this.attrs[k] = String(v); }
  getAttribute(k) { return Object.prototype.hasOwnProperty.call(this.attrs, k) ? this.attrs[k] : null; }
  removeAttribute(k) { delete this.attrs[k]; }
  set hidden(v) { if (v) this.attrs.hidden = ''; else delete this.attrs.hidden; }
  get hidden() { return 'hidden' in this.attrs; }
  addEventListener(t, f) { (this.listeners[t] = this.listeners[t] || []).push(f); }
  click() { if (!('disabled' in this.attrs)) (this.listeners.click || []).forEach((f) => f({ preventDefault() {} })); }
  focus() { doc.activeElement = this; }
  get textContent() { return this.childNodes.map((c) => c.textContent).join(''); }
  set textContent(v) { this.childNodes.forEach((c) => { c.parentNode = null; }); this.childNodes = []; this.appendChild(new TextNode(v)); }
  set innerHTML(v) { throw new Error('innerHTML written'); }
  get innerHTML() { throw new Error('innerHTML read'); }
  set outerHTML(v) { throw new Error('outerHTML written'); }
  insertAdjacentHTML() { throw new Error('insertAdjacentHTML used'); }
  * walk() { yield this; for (const c of this.childNodes) if (c instanceof El) yield* c.walk(); }
  querySelectorAll(sel) { return [...this.walk()].slice(1).filter((e) => matches(e, sel)); }
  querySelector(sel) { return this.querySelectorAll(sel)[0] || null; }
}
function matches(e, sel) {
  let m = sel.match(/^\[([\w-]+)(?:="([^"]*)")?\]$/);
  if (m) return m[2] === undefined ? m[1] in e.attrs : e.attrs[m[1]] === m[2];
  m = sel.match(/^([a-z0-9]*)(?:\.([\w-]+))?$/i);
  if (m) return (!m[1] || e.tagName === m[1].toUpperCase()) && (!m[2] || e.className.split(/\s+/).includes(m[2]));
  throw new Error('selector not supported by the harness: ' + sel);
}

const app = new El('div');
app.attrs.id = 'app';
app.hidden = true;
const doc = {
  readyState: 'complete', activeElement: null, title: '', documentElement: new El('html'),
  createElement: (t) => new El(t), createTextNode: (t) => new TextNode(t),
  getElementById: (id) => (id === 'app' ? app : null), querySelectorAll: (s) => app.querySelectorAll(s),
  addEventListener() {},
};
const winListeners = {};
const loc = { hash: ADVANCE ? START : '#cluster' };
const store = {};
const requests = [];
const sandbox = {
  document: doc, Node: N, location: loc,
  window: { addEventListener: (t, f) => { winListeners[t] = f; }, scrollTo() {} },
  localStorage: { getItem: (k) => store[k] || null, setItem: (k, v) => { store[k] = String(v); } },
  fetch: (url) => {
    requests.push(url);
    const p = path.join(www, url);
    const ok = /^data\/[a-z]+\.json$/.test(url) && fs.existsSync(p);
    return Promise.resolve({
      ok, status: ok ? 200 : 404,
      headers: { get: (k) => (k.toLowerCase() === 'date' ? new Date(clock * 1000).toUTCString() : null) },
      json: () => Promise.resolve(url === 'data/evidence.json' && refreshedEvidence ? refreshedEvidence : JSON.parse(fs.readFileSync(p, 'utf8'))),
    });
  },
  Date: ClockDate,
  setInterval: (fn, ms) => { timers.push({ fn, ms }); }, setTimeout, console,
};
vm.createContext(sandbox);
vm.runInContext(fs.readFileSync(path.join(www, 'app.js'), 'utf8'), sandbox, { filename: 'app.js' });

const settle = () => new Promise((r) => setImmediate(r));
function snapshot() {
  const els = [...app.walk()];
  return {
    text: app.textContent,
    hidden: app.hidden,
    tags: els.reduce((a, e) => { a[e.tagName] = (a[e.tagName] || 0) + 1; return a; }, {}),
    onAttrs: els.filter((e) => Object.keys(e.attrs).some((k) => /^on/i.test(k))).length,
    hrefs: els.filter((e) => e.attrs.href).map((e) => e.attrs.href),
    styleProps: [...new Set(els.flatMap((e) => Object.keys(e.style)))],
  };
}
async function clockRun() {
  const state = () => ({ text: app.textContent,
    banner: (app.querySelector('section.banner') || { className: '' }).className,
    hosts: app.querySelectorAll('article').map((x) => x.className) });
  for (let i = 0; i < 5; i++) await settle();
  const before = state(), fetchesBefore = requests.length;
  clock += ADVANCE;
  for (const timer of timers) timer.fn();
  for (let i = 0; i < 5; i++) await settle();
  return { before, after: state(), refetched: requests.length - fetchesBefore };
}
(async () => {
  if (ADVANCE) { process.stdout.write(JSON.stringify({ clock: await clockRun(), requests })); return; }
  const report = { routes: {}, requests };
  for (let i = 0; i < 5; i++) await settle();
  // every committed scenario run gets its own route (at least two, so an out-of-range index is also rendered)
  let runs = 0;
  try { runs = ((JSON.parse(fs.readFileSync(path.join(www, 'data', 'evidence.json'), 'utf8')).scenarios || {}).runs || []).length; } catch (e) { runs = 0; }
  const scenarioRoutes = Array.from({ length: Math.max(2, runs) }, (_, i) => `#scenarios/${i}`);
  for (const hash of ['#cluster', '#slurm', '#scenarios', ...scenarioRoutes, '#cicd', '#replay/0/actor-A', '#bogus', '#replay/9/%']) {
    loc.hash = hash;
    if (winListeners.hashchange) winListeners.hashchange();
    await settle();
    report.routes[hash] = snapshot();
  }
  // terminal playback: every published screen, jumped to its end (8 Oct)
  report.play = {};
  let evdoc = {};
  try { evdoc = JSON.parse(fs.readFileSync(path.join(www, 'data', 'evidence.json'), 'utf8')); } catch (e) { evdoc = {}; }
  ((evdoc.scenarios || {}).runs || []).forEach((run, i) => (run.terminal || []).forEach((t) => { report.play[run.run_id + '/' + t.name] = null; }));
  for (const key of Object.keys(report.play)) {
    loc.hash = '#play/' + key;
    winListeners.hashchange();
    await settle();
    const end = app.querySelectorAll('button').find((x) => x.attrs['data-key'] === 'play-end');
    if (end) { end.click(); await settle(); }
    report.play[key] = { text: app.textContent, term: (app.querySelector('[data-term]') || { textContent: '' }).textContent, onAttrs: snapshot().onAttrs };
  }
  // Playback controls use a deterministic clock. Evidence refresh inserts a different run
  // before the selected one, as a newly collected run would; playback must keep its identity.
  const playable = Object.keys(report.play).find((key) => report.play[key].term);
  if (playable) {
    loc.hash = '#play/' + playable;
    winListeners.hashchange();
    const click = (key) => app.querySelectorAll('button').find((x) => x.attrs['data-key'] === key).click();
    const tick = () => timers.filter((x) => x.ms === 100).forEach((x) => x.fn());
    const time = () => app.querySelector('[data-term-time]').textContent.split(' / ')[0];
    click('play-restart'); click('play-toggle'); clock += 1; tick();
    const one = time();
    click('play-speed-2'); clock += 1; tick();
    const two = time();
    click('play-toggle'); clock += 2; tick();
    const paused = time();
    const newRun = JSON.parse(JSON.stringify(evdoc.scenarios.runs[0]));
    newRun.run_id = 'new-run-before-the-selected-one';
    refreshedEvidence = JSON.parse(JSON.stringify(evdoc));
    refreshedEvidence.generated_at += 1;
    refreshedEvidence.scenarios.runs.unshift(newRun);
    timers.filter((x) => x.ms === 300000).forEach((x) => x.fn());
    for (let i = 0; i < 5; i++) await settle();
    const refreshed = { time: time(), title: app.querySelectorAll('h2').map((x) => x.textContent).join(' '), term: app.querySelector('[data-term]').textContent };
    click('play-restart');
    report.controls = { run: playable.split('/')[0], one, two, paused, refreshed, restarted: time() };
    refreshedEvidence = null;
  }
  // the replay pager respects its bounds
  loc.hash = '#replay/0/actor-A';
  winListeners.hashchange();
  const pagerState = () => {
    const b = app.querySelectorAll('button').filter((x) => x.attrs['data-key'] === 'prev' || x.attrs['data-key'] === 'next');
    return Object.fromEntries(b.map((x) => [x.attrs['data-key'], 'disabled' in x.attrs]));
  };
  const steps = app.querySelectorAll('button').filter((x) => /^step-/.test(x.attrs['data-key'] || '')).length;
  const first = pagerState();
  for (let i = 0; i < steps + 2; i++) {
    const next = app.querySelectorAll('button').find((x) => x.attrs['data-key'] === 'next');
    if (next) next.click();
  }
  report.pager = { steps, first, last: pagerState(), lastText: app.textContent,
    current: (app.querySelectorAll('button').find((x) => x.attrs['aria-current'] === 'step') || {}).attrs };
  // selecting a timeline event fills the detail
  loc.hash = '#scenarios/0';
  winListeners.hashchange();
  const ev = app.querySelectorAll('button').find((x) => x.className.split(' ').includes('ev') && /OOM/.test(x.textContent));
  if (ev) { ev.click(); report.selected = (app.querySelector('div.detail') || { textContent: '' }).textContent; }
  process.stdout.write(JSON.stringify(report));
})().catch((e) => { process.stdout.write(JSON.stringify({ fatal: String(e && e.stack || e) })); process.exitCode = 1; });
