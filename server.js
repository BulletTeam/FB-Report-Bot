// server.js
// Final consolidated server for Playwright automation + SSE live preview + cookie index
'use strict';

const express = require('express');
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const multer = require('multer');
const cors = require('cors');
const bodyParser = require('body-parser');
const { EventEmitter } = require('events');
const { chromium } = require('playwright');

const app = express();
const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;

// REQUIRED: ADMIN_TOKEN must be set
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || '';
if (!ADMIN_TOKEN) {
  console.error('FATAL: ADMIN_TOKEN not set. export ADMIN_TOKEN="your-token"');
  process.exit(1);
}

// optional envs
const VALIDATE_COOKIES = process.env.VALIDATE_COOKIES === 'true';
const DEFAULT_HEADLESS = process.env.HEADLESS === 'false' ? false : true; // default true; set HEADLESS=false to see browser
const CHROMIUM_PATH = process.env.CHROMIUM_PATH || null;

// directories
const ROOT = path.resolve(__dirname);
const UPLOAD_DIR = path.join(ROOT, 'uploads');
const PUBLIC_DIR = path.join(ROOT, 'public');
const LOG_DIR = path.join(ROOT, 'logs');
const FLOWS_PATH = path.join(ROOT, 'flows.js');

// ensure dirs
for (const d of [UPLOAD_DIR, PUBLIC_DIR, LOG_DIR]) {
  try { if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true }); } catch (e) { console.error('mkdir error', d, e); process.exit(1); }
}

// simple logger: writes to logs/server.log
function simpleLog(...args) {
  try {
    const line = `[${new Date().toISOString()}] ${args.map(a => (typeof a === 'string' ? a : JSON.stringify(a))).join(' ')}\n`;
    fs.appendFileSync(path.join(LOG_DIR, 'server.log'), line);
    console.log(...args);
  } catch (e) { console.error('log-write-error', e); }
}

// load flows.js if exists, otherwise default stub
let flows = { profileSets: [], pageSets: [], postSets: [] };
try {
  if (fs.existsSync(FLOWS_PATH)) {
    flows = require(FLOWS_PATH);
    simpleLog('flows loaded', Object.keys(flows || {}));
  } else simpleLog('flows.js not found, using empty sets');
} catch (e) {
  simpleLog('error loading flows.js', e && e.message);
  flows = { profileSets: [], pageSets: [], postSets: [] };
}
if (!Array.isArray(flows.profileSets) || !flows.profileSets.length) flows.profileSets = [{ id:'default', name:'default', steps: [] }];
if (!Array.isArray(flows.pageSets) || !flows.pageSets.length) flows.pageSets = [{ id:'default', name:'default', steps: [] }];
if (!Array.isArray(flows.postSets) || !flows.postSets.length) flows.postSets = [{ id:'default', name:'default', steps: [] }];

// Playwright launch helper (respects CHROMIUM_PATH and headless options)
async function resolveExecutablePath() {
  if (CHROMIUM_PATH && fs.existsSync(CHROMIUM_PATH)) return CHROMIUM_PATH;
  return null;
}
async function launchBrowserWithFallback(opts = {}) {
  const execPath = await resolveExecutablePath();

  // Determine headless: prefer explicit opts.headless, else env HEADLESS, else default true
  let headless;
  if (typeof opts.headless === 'boolean') headless = opts.headless;
  else if (process.env.HEADLESS !== undefined) headless = !(String(process.env.HEADLESS).toLowerCase() === 'false');
  else headless = true; // safe default

  // If there's no DISPLAY (no X server) — force headless true.
  if (!process.env.DISPLAY) {
    headless = true;
  }

  const launchOpts = {
    headless,
    args: (opts.args || []).concat([
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-dev-shm-usage',
      '--disable-gpu',
      '--disable-software-rasterizer',
      '--disable-extensions',
      '--disable-background-timer-throttling'
    ])
  };

  if (execPath) launchOpts.executablePath = execPath;

  simpleLog('Launching Playwright Chromium', execPath ? ('from ' + execPath) : '(playwright managed)', 'headless=' + headless);
  try {
    const browser = await chromium.launch(launchOpts);
    return browser;
  } catch (err) {
    simpleLog('playwright.launch failed:', err && err.message);
    throw err;
  }
}

// ---------------- COOKIE INDEX storage -----------------
const COOKIE_INDEX_PATH = path.join(UPLOAD_DIR, 'cookies_index.json');
let COOKIE_INDEX = { cookies: [], counts: { total:0, live:0, invalid:0, parsed:0, error:0 } };

function recalcCounts() {
  COOKIE_INDEX.counts = { total: COOKIE_INDEX.cookies.length, live:0, invalid:0, parsed:0, error:0 };
  for (const c of COOKIE_INDEX.cookies) {
    const s = c.validateResult && c.validateResult.status ? c.validateResult.status : (c.isAccount ? 'parsed' : 'invalid');
    if (s === 'live') COOKIE_INDEX.counts.live++;
    else if (s === 'invalid') COOKIE_INDEX.counts.invalid++;
    else if (s === 'error') COOKIE_INDEX.counts.error++;
    if (c.isAccount) COOKIE_INDEX.counts.parsed++;
  }
}
try {
  if (fs.existsSync(COOKIE_INDEX_PATH)) {
    const raw = fs.readFileSync(COOKIE_INDEX_PATH, 'utf8');
    COOKIE_INDEX = JSON.parse(raw);
    if (!COOKIE_INDEX.cookies) COOKIE_INDEX.cookies = [];
    recalcCounts();
  }
} catch (e) { simpleLog('cookieIndex-load-error', e && e.message); }
function saveCookieIndex() {
  try { recalcCounts(); fs.writeFileSync(COOKIE_INDEX_PATH, JSON.stringify(COOKIE_INDEX, null, 2)); }
  catch (e) { simpleLog('cookieIndex-save-err', e && e.message); }
}

// helper: parse line "k1=v1; k2=v2" -> {kv, hasCUser, hasXs, isAccount}
function parseLineToKv(line) {
  const parts = String(line || '').split(';').map(p => p.trim()).filter(Boolean);
  const kv = {};
  for (const p of parts) {
    const idx = p.indexOf('=');
    if (idx === -1) continue;
    const k = p.slice(0, idx).trim();
    const v = p.slice(idx+1).trim();
    kv[k] = v;
  }
  const hasCUser = !!kv['c_user'] || !!kv['cuser'] || !!kv['cuserid'];
  const hasXs = !!kv['xs'] || !!kv['XS'] || !!kv['Xs'];
  return { kv, hasCUser, hasXs, isAccount: hasCUser && hasXs };
}

function loadCookieAccountsFromFile() {
  const out = [];
  const cookieTxt = path.join(UPLOAD_DIR, 'cookies.txt');
  try {
    if (fs.existsSync(cookieTxt)) {
      const lines = fs.readFileSync(cookieTxt, 'utf-8').split(/\r?\n|\r|\n/g).map(l => l.trim()).filter(Boolean);
      for (const l of lines) {
        const parsed = parseLineToKv(l);
        if (parsed && parsed.isAccount) out.push(parsed.kv);
      }
    } else {
      const files = fs.readdirSync(UPLOAD_DIR).filter(f => f.endsWith('.txt'));
      for (const f of files) {
        if (f === 'cookies.txt') continue;
        const content = fs.readFileSync(path.join(UPLOAD_DIR, f), 'utf-8').trim();
        if (!content) continue;
        const parsed = parseLineToKv(content);
        if (parsed && parsed.isAccount) out.push(parsed.kv);
      }
    }
  } catch (e) { simpleLog('loadCookieAccounts-error', e && e.message); }
  return out;
}

// helper snippet (mask xs)
function makeSnippetFromKv(line, kv) {
  try {
    if (kv && (kv.c_user || kv.cuserid || kv.cuser)) {
      const id = (kv.c_user || kv.cuserid || kv.cuser || '').toString();
      const shortId = id.length > 8 ? id.slice(0,6) + '...' : id;
      let xsVal = kv.xs || kv.XS || kv.Xs || kv['xs'];
      if (xsVal) {
        xsVal = xsVal.toString();
        const end = xsVal.length > 6 ? xsVal.slice(-4) : xsVal;
        return `acct:${shortId}, xs:••••${end}`;
      }
      return `acct:${shortId}`;
    }
    if (kv && (kv.id || kv.uid)) {
      const id = (kv.id || kv.uid).toString();
      return `id:${ id.length > 8 ? id.slice(0,6) + '...' : id }`;
    }
    const crypto = require('crypto');
    const h = crypto.createHash('sha1').update(line || '').digest('hex').slice(0,8);
    return `line#${h}`;
  } catch (e) {
    if (!line) return '';
    return line.length > 60 ? line.slice(0,40) + '...' : line;
  }
}

// ---------------- SSE sessions ----------------
const sessions = new Map();
function getSession(sid = 'default') {
  if (!sessions.has(sid)) {
    sessions.set(sid, {
      clients: new Set(),
      running: false,
      abort: false,
      emitter: new EventEmitter(),
      logs: [],
      browser: null,
      contexts: [],
      pages: [],
      currentPage: null,
      currentContext: null,
      previewIntervals: new Map()
    });
  }
  return sessions.get(sid);
}
function sseSend(sid, event, payload) {
  const sess = getSession(sid);
  const pretty = `${new Date().toLocaleTimeString()} ${event} ${JSON.stringify(payload)}`;
  sess.logs.push(pretty);
  if (sess.logs.length > 2000) sess.logs.shift();
  simpleLog('SSE', sid, event, payload);
  for (const res of sess.clients) {
    try {
      if (event && event !== 'message') res.write(`event: ${event}\n`);
      res.write(`data: ${JSON.stringify(payload)}\n\n`);
    } catch (e) {
      // remove broken client
      try { sess.clients.delete(res); } catch(_) {}
    }
  }
}

// UTIL: clear all preview intervals for a session (very important)
function clearAllPreviewIntervals(sessionId) {
  const sess = getSession(sessionId);
  try {
    for (const [idObj, info] of sess.previewIntervals.entries()) {
      try {
        clearInterval(info.intervalId || idObj);
      } catch (e) {}
      sess.previewIntervals.delete(idObj);
    }
  } catch (e) { simpleLog('clearAllPreviewIntervals-error', e && e.message); }
}

// attachLivePreview(page): periodically screenshot and send base64 via SSE 'screenshot' event
function attachLivePreview(sessionId, page, opts = {}) {
  const intervalMs = Number(opts.intervalMs || 3000);
  const sess = getSession(sessionId);
  let stopped = false;

  const id = setInterval(async () => {
    if (stopped) return;
    try {
      if (!page || (typeof page.isClosed === 'function' ? page.isClosed() : false)) {
        clearInterval(id);
        try { sess.previewIntervals.delete(id); } catch(_) {}
        return;
      }
      // take screenshot; small size for speed
      const buf = await page.screenshot({ fullPage:false }).catch(()=>null);
      if (!buf) return;
      // send as raw base64 string payload (server's live.html accepts raw base64 or {data:...})
      sseSend(sessionId, 'screenshot', buf.toString('base64'));
    } catch (e) {
      simpleLog('attachLivePreview-screenshot-err', e && e.message ? e.message : String(e));
    }
  }, Math.max(600, intervalMs));

  // store handle so we can clear later
  sess.previewIntervals.set(id, { intervalId: id, page });
  return id;
}

// ---------------- quickValidateCookie (light-weight) ----------------
async function quickValidateCookie(cookies, sessionId) {
  if (!VALIDATE_COOKIES) return { status: 'parsed', reason: 'validation-disabled' };
  if (!Array.isArray(cookies) || !cookies.length) return { status:'error', reason:'no-cookies' };

  let browser = null, context = null, page = null;
  const start = Date.now();
  try {
    browser = await launchBrowserWithFallback({ headless: true });
    context = await browser.newContext({
      viewport: { width:360, height:800 },
      userAgent: 'Mozilla/5.0 (Linux; Android 10; Mobile) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Mobile Safari/537.36'
    });
    page = await context.newPage();

    const pwCookies = cookies.map(c => ({
      name: c.name,
      value: String(c.value),
      domain: c.domain || '.facebook.com',
      path: c.path || '/',
      httpOnly: !!c.httpOnly,
      secure: !!c.secure,
      sameSite: c.sameSite || 'Lax'
    }));

    await page.goto('https://m.facebook.com', { waitUntil: 'domcontentloaded', timeout: 20000 }).catch(()=>{});
    try { await context.addCookies(pwCookies); } catch (e) {
      sseSend(sessionId, 'log', { msg: 'quickValidate: context.addCookies failed', error: e && e.message });
      return { status: 'error', reason: 'cookie-set-failed' };
    }
    await page.goto('https://m.facebook.com', { waitUntil: 'domcontentloaded', timeout: 20000 }).catch(()=>{});
    await page.waitForTimeout(1000);

    let curUrl = page.url ? page.url() : null;
    let html = '';
    try { html = await page.content(); } catch (e) { html = ''; }

    const lower = String(html || '').toLowerCase();
    const loginHints = ['log in to see posts','log in to see','log in','create new account','password','sign up','please log in'];
    for (const h of loginHints) if (lower.includes(h)) {
      sseSend(sessionId, 'log', { msg: 'quickValidate result: invalid (login detected)', url: curUrl });
      return { status: 'invalid', reason: 'login-prompt-or-redirect', url: curUrl };
    }

    const hasProfileMarker = lower.includes('see more from') || lower.includes('profile photo') || /\/p\/[A-Za-z0-9\-]+/.test(lower);
    if (hasProfileMarker) {
      sseSend(sessionId, 'log', { msg: 'quickValidate result: live (profile markers found)', url: curUrl });
      return { status: 'live', reason: 'profile-markers', url: curUrl };
    }

    sseSend(sessionId, 'log', { msg: 'quickValidate fallback: considered live', url: curUrl });
    return { status: 'live', reason: 'no-login-detected', url: curUrl };
  } catch (e) {
    sseSend(sessionId, 'log', { msg:'quickValidate error', error: e && e.message ? e.message : String(e) });
    return { status: 'error', reason: e && e.message ? e.message : String(e) };
  } finally {
    try { if (page) await page.close(); } catch(_) {}
    try { if (context) await context.close(); } catch(_) {}
    try { if (browser) await browser.close(); } catch(_) {}
    sseSend(sessionId, 'log', { msg: 'quickValidate took ms', ms: Date.now() - start });
  }
}

// ----------------- robust runFlowOnPage (retries + postCheck) -----------------
async function runFlowOnPage(page, flowSteps, opts = {}) {
  const { sessionId='default', perActionDelay=1100, actionTimeout=15000, maxAttempts=3 } = opts;
  function sleep(ms){ return new Promise(r=>setTimeout(r, ms)); }

  async function singleClickAttempt({ type, value, timeout }) {
    // uses Playwright locator APIs
    try {
      if (type === 'css') {
        const loc = page.locator(value).first();
        await loc.waitFor({ timeout });
        await loc.click({ timeout, force: true });
        return true;
      }
      if (type === 'xpath') {
        const loc = page.locator(`xpath=${value}`).first();
        await loc.waitFor({ timeout });
        await loc.click({ timeout, force: true });
        return true;
      }
      if (type === 'text') {
        try {
          const byText = page.getByText(value, { exact: false }).first();
          await byText.waitFor({ timeout });
          await byText.click({ timeout, force: true });
          return true;
        } catch (_) {
          const lower = value.toLowerCase().replace(/'/g, "\\'");
          const xp = `//*[contains(translate(normalize-space(string(.)),'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz'),'${lower}')]`;
          const loc2 = page.locator(`xpath=${xp}`).first();
          await loc2.waitFor({ timeout });
          await loc2.click({ timeout, force: true });
          return true;
        }
      }
      // autodetect
      if (!type) {
        try {
          const loc = page.locator(value).first();
          await loc.waitFor({ timeout });
          await loc.click({ timeout, force: true });
          return true;
        } catch (_) {}
        try {
          const loc = page.locator(`xpath=${value}`).first();
          await loc.waitFor({ timeout });
          await loc.click({ timeout, force: true });
          return true;
        } catch (_) {}
        const lower = String(value).toLowerCase().replace(/'/g, "\\'");
        const xp2 = `//*[contains(translate(normalize-space(string(.)),'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz'),'${lower}')]`;
        const loc2 = page.locator(`xpath=${xp2}`).first();
        await loc2.waitFor({ timeout });
        await loc2.click({ timeout, force: true });
        return true;
      }
    } catch (e) {
      throw e;
    }
  }

  async function trySelector(selRaw, config = {}) {
    const attempts = config.attempts || maxAttempts;
    const timeout = config.timeout || Math.min(actionTimeout, 7000);
    const recovery = Array.isArray(config.recoverySelectors) ? config.recoverySelectors : [];
    let lastError = null;

    // parse type
    let type = null, value = selRaw;
    if (/^css:/.test(selRaw)) { type = 'css'; value = selRaw.replace(/^css:/,'').trim(); }
    else if (/^xpath:/.test(selRaw)) { type = 'xpath'; value = selRaw.replace(/^xpath:/,'').trim(); }
    else if (/^text:/.test(selRaw)) { type = 'text'; value = selRaw.replace(/^text:/,'').trim(); }
    else { type = null; value = selRaw; }

    for (let i=0;i<attempts;i++){
      try {
        // attempt to scroll into view
        try {
          if (type === 'css') {
            const loc = page.locator(value).first();
            await loc.scrollIntoViewIfNeeded({ timeout: Math.min(2000, timeout) }).catch(()=>{});
          } else {
            const loc = page.locator(type === 'xpath' ? `xpath=${value}` : value).first();
            await loc.scrollIntoViewIfNeeded({ timeout: Math.min(2000, timeout) }).catch(()=>{});
          }
        } catch (_) {}
        await singleClickAttempt({ type, value, timeout });
        return { ok:true, attempt:i+1 };
      } catch (e) {
        lastError = e;
        await sleep(300 + Math.floor(Math.random()*300));
      }
    }

    // recovery attempts (if provided)
    for (const r of recovery) {
      try {
        try { await singleClickAttempt({ type: null, value: r, timeout: Math.min(3000, timeout) }); } catch(_) {}
        try {
          await sleep(250);
          await singleClickAttempt({ type, value, timeout });
          return { ok:true, recovered:true };
        } catch (e2) { lastError = e2; }
      } catch(_) {}
    }

    return { ok:false, error: lastError };
  }

  async function postCheckOk(check) {
    if (!check) return true;
    try {
      if (/^css:/.test(check)) {
        await page.waitForSelector(check.replace(/^css:/,''), { timeout: 3000 });
        return true;
      } else if (/^xpath:/.test(check)) {
        await page.waitForSelector(`xpath=${check.replace(/^xpath:/,'')}`, { timeout: 3000 });
        return true;
      } else if (/^text:/.test(check)) {
        const txt = check.replace(/^text:/,'').trim();
        const lower = txt.toLowerCase().replace(/'/g,"\\'");
        const xp = `//*[contains(translate(normalize-space(string(.)),'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz'),'${lower}')]`;
        await page.waitForSelector(`xpath=${xp}`, { timeout: 3000 });
        return true;
      } else {
        try { await page.waitForSelector(check, { timeout: 2500 }); return true; } catch(_) {}
        const lower = String(check).toLowerCase().replace(/'/g,"\\'");
        const xp2 = `//*[contains(translate(normalize-space(string(.)),'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz'),'${lower}')]`;
        await page.waitForSelector(`xpath=${xp2}`, { timeout: 2500 });
        return true;
      }
    } catch (e) { return false; }
  }

  // main
  for (const step of flowSteps) {
    if (getSession(sessionId).abort) throw new Error('ABORTED');
    const label = step.label || step.selector || step.text || 'step';
    sseSend(sessionId, 'log', { step: label });

    const selectors = Array.isArray(step.selectors) ? step.selectors : (step.selector ? [step.selector] : []);
    const attemptsForStep = step.attempts || maxAttempts;
    const recoverySelectors = step.recoverySelectors || [];
    const mandatory = !!step.mandatory;
    const postCheck = step.postCheck || null;

    let stepOk = false;
    let lastDetail = null;

    for (const sel of selectors) {
      const res = await trySelector(sel, { attempts: attemptsForStep, timeout: Math.min(actionTimeout, 8000), recoverySelectors });
      if (res.ok) { stepOk = true; lastDetail = res; break; }
      lastDetail = res.error || res;
    }

    if (stepOk && postCheck) {
      const ok = await postCheckOk(postCheck);
      if (!ok) {
        let pcOk = false;
        for (let r=0;r<2 && !pcOk;r++) {
          await sleep(300);
          pcOk = await postCheckOk(postCheck);
        }
        if (!pcOk) {
          stepOk = false;
          lastDetail = { postCheckFailed: true };
        }
      }
    }

    if (!stepOk) {
      sseSend(sessionId, 'warn', { step: label, error: 'selector-not-found-or-postcheck-failed', detail: (lastDetail && lastDetail.error) ? (lastDetail.error.message || String(lastDetail.error)) : String(lastDetail) });
      if (mandatory) throw new Error(`Mandatory step failed: ${label}`);
    } else {
      sseSend(sessionId, 'info', { step: label, ok: true, detail: lastDetail });
    }

    await sleep(Number(step.waitMs || perActionDelay) + Math.floor(Math.random()*350));
  }
}

// ---------------- main runner: reportRunner ----------------
async function reportRunner(sessionId, opts = {}) {
  const sess = getSession(sessionId);
  try {
    sess.running = true; sess.abort = false;
    let cookieAccounts = loadCookieAccountsFromFile();
    const MAX_ACCOUNTS = Math.max(1, parseInt(process.env.MAX_ACCOUNTS || '200', 10));
    if (cookieAccounts.length > MAX_ACCOUNTS) cookieAccounts = cookieAccounts.slice(0, MAX_ACCOUNTS);
    if (!cookieAccounts.length) { sseSend(sessionId,'error',{msg:'No cookie accounts found'}); sess.running=false; return; }

    const target = String(opts.targetUrl || opts.target || '').trim();
    if (!target) { sseSend(sessionId,'error',{msg:'targetUrl required'}); sess.running=false; return; }

    const kind = (opts.setType || opts.type || 'profile').toLowerCase();
    const sets = kind === 'profile' ? flows.profileSets || [] : kind === 'page' ? flows.pageSets || [] : flows.postSets || [];
    if (!sets.length) { sseSend(sessionId,'error',{msg:'No flow sets for '+kind}); sess.running=false; return; }
    const found = opts.setId ? sets.find(s => s.id===opts.setId || s.name===opts.setId) : sets[0];
    if (!found) { sseSend(sessionId,'error',{msg:'Requested set not found'}); sess.running=false; return; }

    // local helper to launch the browser once and reuse; restart periodically
    async function launchBrowser() { return await launchBrowserWithFallback({ headless: !!opts.headless, args: opts.args || [], defaultViewport: opts.defaultViewport }); }

    let browser = await launchBrowser();
    sess.browser = browser;
    let sinceRestart = 0;
    const RESTART_AFTER = Math.max(5, parseInt(process.env.RESTART_AFTER || '25',10));
    let accountIndex = 0;

    for (const cookies of cookieAccounts) {
      if (sess.abort) break;
      accountIndex++;

      // normalize cookie input -> array of {name,value,...}
      let accountCookies = [];
      if (Array.isArray(cookies)) accountCookies = cookies.flat(Infinity).filter(Boolean);
      else if (cookies && typeof cookies === 'object') {
        if (cookies.name && cookies.value) accountCookies = [cookies];
        else accountCookies = Object.entries(cookies).map(([k,v]) => ({ name:k, value:String(v), domain:'.facebook.com', path:'/', httpOnly:false, secure:true }));
      } else {
        sseSend(sessionId, 'warn', { msg: 'Skipping malformed cookie entry', index: accountIndex });
        continue;
      }
      accountCookies = accountCookies.filter(c => c && c.name && (c.value !== undefined));
      const accId = accountCookies.find(c => c.name === 'c_user')?.value || `acct_${accountIndex}`;
      sseSend(sessionId, 'info', { msg:`Account ${accountIndex}`, account: accId });

      let page = null, context = null;
      try {
        if (sinceRestart >= RESTART_AFTER) {
          try { await browser.close(); } catch(e){ simpleLog('browser-close-error', e && e.message); }
          browser = await launchBrowser();
          sess.browser = browser;
          sinceRestart = 0;
          sseSend(sessionId,'info',{msg:'Browser restarted to avoid memory leak'});
        }

        context = await browser.newContext({
          viewport: opts.defaultViewport || { width:390, height:844 },
          userAgent: 'Mozilla/5.0 (Linux; Android 10; Mobile) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Mobile Safari/537.36'
        });
        page = await context.newPage();

        sess.contexts.push(context);
        sess.pages.push(page);
        sess.currentContext = context;
        sess.currentPage = page;

        simpleLog('page-created-for-account', accId);
        sseSend(sessionId, 'info', { msg: 'page-created', account: accId });

        const pwCookies = accountCookies.map(c => ({
          name: c.name,
          value: String(c.value),
          domain: c.domain || '.facebook.com',
          path: c.path || '/',
          httpOnly: !!c.httpOnly,
          secure: !!c.secure,
          sameSite: c.sameSite || 'Lax'
        }));

        // set cookies and navigate
        await page.goto('https://www.facebook.com', { waitUntil: 'domcontentloaded', timeout: 20000 }).catch(()=>{});
        if (pwCookies.length) {
          try {
            await context.addCookies(pwCookies);
          } catch (e) {
            sseSend(sessionId, 'warn', { msg: 'context.addCookies failed', account: accId, error: e && e.message });
          }
        } else {
          sseSend(sessionId, 'warn', { msg: 'No cookies to set for account', account: accId });
        }

        // attach live preview (3s default) for this page
        try {
          attachLivePreview(sessionId, page, { intervalMs: opts.previewIntervalMs || 3000 });
        } catch (e) { simpleLog('attachLivePreview error', e && e.message); }

        await page.goto(target, { waitUntil: 'domcontentloaded', timeout: 30000 }).catch(()=>{});
        try { const curUrl = await page.url(); simpleLog('Page navigated', { account: accId, url: curUrl }); sseSend(sessionId,'info',{msg:'page-url',url:curUrl}); } catch(e){}

        await page.waitForTimeout(1200 + Math.floor(Math.random()*800));

        const ACCOUNT_TIMEOUT_MS = Math.max(30_000, parseInt(process.env.ACCOUNT_TIMEOUT_MS || '90000',10));
        await Promise.race([
          runFlowOnPage(page, found.steps, { sessionId, perActionDelay: opts.perActionDelay || 1200, actionTimeout: opts.actionTimeout || 12000 }),
          new Promise((_, rej) => setTimeout(() => rej(new Error('Account timeout')), ACCOUNT_TIMEOUT_MS))
        ]);

        sseSend(sessionId, 'success', { account: accId, msg: 'Flow completed' });

        try { await page.close(); } catch(e){}
        try { await context.close(); } catch(e){}
        sess.pages = sess.pages.filter(p => p !== page);
        sess.contexts = sess.contexts.filter(c => c !== context);
        sess.currentPage = null;
        sess.currentContext = null;
      } catch (err) {
        sseSend(sessionId,'error',{account: accId, error: err && err.message ? err.message : String(err)});
        try { if (page) await page.close(); } catch(e){}
        try { if (context) await context.close(); } catch(e){}
        sess.pages = sess.pages.filter(p => p !== page);
        sess.contexts = sess.contexts.filter(c => c !== context);
        sess.currentPage = null;
        sess.currentContext = null;
      }

      sinceRestart++;
      await new Promise(r => setTimeout(r, (opts.gapMs || 2500) + Math.floor(Math.random()*2000)));
    } // end accounts loop

    // cleanup
    try {
      // clear preview intervals explicitly
      clearAllPreviewIntervals(sessionId);

      if (browser) {
        try { await browser.close(); } catch (e) { simpleLog('browser-close-final', e && e.message); }
      }
      sess.browser = null;
      sess.contexts = [];
      sess.pages = [];
      sess.currentPage = null;
      sess.currentContext = null;
      sseSend(sessionId, 'done', { msg: 'Runner finished' });
    } catch (e) {
      sseSend(sessionId, 'fatal', { msg: e && e.message ? e.message : String(e) });
      simpleLog('reportRunner-final-error', e && e.stack ? e.stack : String(e));
    } finally {
      sess.running = false;
      sess.abort = false;
    }
  } catch (e) {
    sseSend(sessionId, 'fatal', { msg: e && e.message ? e.message : String(e) });
    simpleLog('reportRunner-fatal', e && e.stack ? e.stack : String(e));
    const s = getSession(sessionId);
    s.running = false;
    s.abort = false;
  }
}

// ---------- multer for uploads ----------
const sanitize = (name) => String(name || 'file').replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 200);
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => cb(null, `${Date.now()}-${Math.floor(Math.random()*10000)}-${sanitize(path.basename(file.originalname))}`)
});
const upload = multer({
  storage,
  limits: { fileSize: 50 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const ok = /text\/|plain/.test(file.mimetype) || file.originalname.toLowerCase().endsWith('.txt');
    if (!ok) return cb(new Error('Only .txt allowed'));
    cb(null, true);
  }
});

// express middleware
app.use(cors());
app.use(bodyParser.json({ limit: '20mb' }));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(PUBLIC_DIR));

// admin middleware
function requireAdmin(req, res, next) {
  const t = req.headers['x-admin-token'] || req.body.adminToken || req.query.adminToken;
  if (!t || t !== ADMIN_TOKEN) {
    simpleLog('unauthorized', { ip: req.ip, path: req.path });
    return res.status(401).json({ ok:false, message:'Unauthorized' });
  }
  next();
}

// ---------- API endpoints ----------

// SSE events
app.get('/events', requireAdmin, (req, res) => {
  const sid = req.query.sessionId || 'default';
  const sess = getSession(sid);

  res.set({
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'X-Accel-Buffering': 'no'
  });
  res.flushHeaders();

  res.write(`event: ready\ndata: ${JSON.stringify({ msg: 'SSE connected', sessionId: sid })}\n\n`);
  sess.clients.add(res);

  // keepalive comment every 15s
  const ka = setInterval(() => {
    try { res.write(':\n\n'); } catch (e) {}
  }, 15000);

  req.on('close', () => {
    clearInterval(ka);
    sess.clients.delete(res);
  });
});

// debug screenshot for current page (admin)
app.get('/debug-screenshot', requireAdmin, async (req, res) => {
  const sessionId = req.query.sessionId || 'default';
  const sess = getSession(sessionId);
  if (!sess.currentPage) return res.status(400).send('No active page for session ' + sessionId);
  try {
    const buf = await sess.currentPage.screenshot({ fullPage: false });
    res.set('Content-Type','image/png');
    res.send(buf);
  } catch (e) {
    simpleLog('debug-screenshot-error', e && e.message);
    res.status(500).send('Screenshot error: ' + (e && e.message || 'err'));
  }
});

// debug html
app.get('/debug-html', requireAdmin, async (req, res) => {
  const sessionId = req.query.sessionId || 'default';
  const sess = getSession(sessionId);
  if (!sess.currentPage) return res.status(400).send('No active page for session ' + sessionId);
  try {
    const html = await sess.currentPage.content();
    res.set('Content-Type','text/plain; charset=utf-8');
    res.send(html);
  } catch (e) {
    simpleLog('debug-html-error', e && e.message);
    res.status(500).send('HTML error: ' + (e && e.message || 'err'));
  }
});

// flows list
app.get('/flows', (req, res) => res.json(flows));

// upload cookies (multipart or text)
let uploadLock = false;
app.post('/uploadCookies', requireAdmin, upload.single('cookies'), async (req, res) => {
  const sessionId = req.query.sessionId || req.body.sessionId || 'default';
  if (uploadLock) return res.status(409).json({ ok:false, message:'Another upload in progress' });
  uploadLock = true;

  try {
    let raw = '';
    if (req.file) {
      const target = path.join(UPLOAD_DIR, 'cookies.txt');
      await fsp.copyFile(req.file.path, target);
      try { await fsp.unlink(req.file.path); } catch (_) {}
      raw = await fsp.readFile(target, 'utf8');
      sseSend(sessionId, 'log', { msg: 'cookies file saved', file: 'uploads/cookies.txt' });
    } else if (req.body && req.body.text) {
      raw = String(req.body.text || '').trim();
      if (!raw) { uploadLock = false; return res.status(400).json({ ok:false, message:'Empty text' }); }
      await fsp.writeFile(path.join(UPLOAD_DIR,'cookies.txt'), raw, 'utf8');
      sseSend(sessionId, 'log', { msg: 'cookies written from text' });
    } else {
      uploadLock = false;
      return res.status(400).json({ ok:false, message:'No file or text' });
    }

    const lines = raw.split(/\r?\n|\r|\n/g).map(l => l.trim()).filter(Boolean);
    if (!lines.length) {
      sseSend(sessionId, 'warn', { msg: 'No cookie lines found in file' });
      uploadLock = false;
      return res.json({ ok:true, parsed: 0 });
    }

    // reset index
    COOKIE_INDEX.cookies = [];
    saveCookieIndex();

    let parsedCount = 0;
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      try {
        const { kv, hasCUser, hasXs, isAccount } = parseLineToKv(line);
        const snippet = makeSnippetFromKv(line, kv);
        const summary = { lineIndex: i + 1, snippet, hasCUser, hasXs, isAccount };

        if (!isAccount) {
          sseSend(sessionId, 'cookieStatus', { status: 'invalid', reason: 'missing c_user/xs', ...summary });
          COOKIE_INDEX.cookies.push({
            lineIndex: i + 1, originalLine: line, snippet, hasCUser, hasXs, isAccount, parsedAt: (new Date()).toISOString(),
            validateResult: { status: 'invalid', reason: 'missing c_user/xs' }
          });
          saveCookieIndex();
          continue;
        }

        parsedCount++;
        sseSend(sessionId, 'cookieStatus', { status: 'parsed', ...summary });

        const cookieObjects = [];
        for (const [k,v] of Object.entries(kv || {})) {
          if (k && v !== undefined) {
            cookieObjects.push({ name:k, value:String(v), domain:'.facebook.com', path:'/', httpOnly:false, secure:true });
          }
        }

        sseSend(sessionId, 'log', { msg: `Validating account line ${i+1}` });

        let result = { status: 'parsed', reason: 'validation-skipped' };
        if (VALIDATE_COOKIES) {
          try { result = await quickValidateCookie(cookieObjects, sessionId); } catch (err) { result = { status: 'error', reason: err && err.message ? err.message : String(err) }; }
        } else { result = { status: 'parsed', reason: 'validation-disabled' }; }

        if (result.status === 'live') sseSend(sessionId, 'cookieStatus', { status:'live', lineIndex:i+1, reason: result.reason, url: result.url || null });
        else if (result.status === 'invalid') sseSend(sessionId, 'cookieStatus', { status:'invalid', lineIndex:i+1, reason: result.reason, url: result.url || null });
        else if (result.status === 'parsed') sseSend(sessionId, 'cookieStatus', { status:'parsed', lineIndex:i+1, reason: result.reason });
        else sseSend(sessionId, 'cookieStatus', { status:'error', lineIndex:i+1, reason: result.reason });

        COOKIE_INDEX.cookies.push({
          lineIndex: i + 1, originalLine: line, snippet, hasCUser, hasXs, isAccount, parsedAt: (new Date()).toISOString(), validateResult: result
        });
        saveCookieIndex();

        await new Promise(r => setTimeout(r, 600 + Math.floor(Math.random() * 400)));
      } catch (lineErr) {
        simpleLog('uploadCookies-line-error', { lineIndex: i + 1, error: lineErr && lineErr.message ? lineErr.message : String(lineErr) });
        sseSend(sessionId, 'cookieStatus', { status: 'error', lineIndex: i + 1, reason: lineErr && lineErr.message ? lineErr.message : String(lineErr) });
        COOKIE_INDEX.cookies.push({
          lineIndex: i + 1, originalLine: line, snippet: (line.length > 60 ? line.slice(0,40) + '...' : line),
          hasCUser: false, hasXs: false, isAccount: false, parsedAt: (new Date()).toISOString(),
          validateResult: { status: 'error', reason: lineErr && lineErr.message ? lineErr.message : String(lineErr) }
        });
        saveCookieIndex();
        continue;
      }
    }

    sseSend(sessionId, 'log', { msg:`Parsed ${parsedCount} account cookie(s)` });
    uploadLock = false;
    return res.json({ ok:true, parsed: parsedCount, totalLines: lines.length });
  } catch (e) {
    uploadLock = false;
    simpleLog('uploadCookies-error', e && e.message);
    sseSend(sessionId, 'error', { msg: 'upload handler error', error: e && e.message });
    return res.status(500).json({ ok:false, error: e && e.message ? e.message : String(e) });
  }
});

// cookie list
app.get('/cookieList', requireAdmin, (req,res) => {
  recalcCounts();
  res.json({
    total: COOKIE_INDEX.cookies.length,
    counts: COOKIE_INDEX.counts,
    cookies: COOKIE_INDEX.cookies
  });
});

// get single cookie
app.get('/cookie/:lineIndex', requireAdmin, (req,res) => {
  const idx = parseInt(req.params.lineIndex, 10);
  if (!idx) return res.status(400).json({ ok:false, message:'bad index' });
  const found = COOKIE_INDEX.cookies.find(c => c.lineIndex === idx);
  if (!found) return res.status(404).json({ ok:false, message:'not found' });
  res.json({ ok:true, cookie: found });
});

// clear cookie index
app.post('/cookieIndex/clear', requireAdmin, (req,res) => {
  COOKIE_INDEX = { cookies: [], counts: { total:0, live:0, invalid:0, parsed:0, error:0 } };
  saveCookieIndex();
  res.json({ ok:true });
});

// QUICK upload: no validation, just save lines and index them as 'parsed: uploaded-quick'
app.post('/uploadQuick', requireAdmin, upload.single('cookies'), async (req, res) => {
  const sessionId = req.query.sessionId || req.body.sessionId || 'default';
  try {
    let raw = '';
    if (req.file) {
      const target = path.join(UPLOAD_DIR, 'cookies.txt');
      await fsp.copyFile(req.file.path, target);
      try { await fsp.unlink(req.file.path); } catch(_) {}
      raw = await fsp.readFile(target, 'utf8');
      sseSend(sessionId, 'log', { msg: 'quick-upload: cookies file saved' });
    } else if (req.body && req.body.text) {
      raw = String(req.body.text || '').trim();
      if (!raw) return res.status(400).json({ ok:false, message:'Empty text' });
      await fsp.writeFile(path.join(UPLOAD_DIR,'cookies.txt'), raw, 'utf8');
      sseSend(sessionId, 'log', { msg: 'quick-upload: cookies written from text' });
    } else {
      return res.status(400).json({ ok:false, message:'No file or text' });
    }

    const lines = raw.split(/\r?\n|\r|\n/g).map(l => l.trim()).filter(Boolean);
    if (!lines.length) return res.json({ ok:true, parsed: 0, totalLines:0 });

    // reset index
    COOKIE_INDEX.cookies = [];

    for (let i=0;i<lines.length;i++){
      const line = lines[i];
      const { kv, hasCUser, hasXs, isAccount } = parseLineToKv(line);
      const snippet = makeSnippetFromKv(line, kv);

      // insert into index AS PARSED but mark validation skipped (uploaded-quick)
      COOKIE_INDEX.cookies.push({
        lineIndex: i+1,
        originalLine: line,
        snippet,
        hasCUser, hasXs, isAccount,
        parsedAt: (new Date()).toISOString(),
        validateResult: { status: 'parsed', reason: 'uploaded-quick' }
      });

      // notify via SSE that a cookie was indexed (optional)
      sseSend(sessionId, 'cookieStatus', { status: 'parsed', lineIndex: i+1, snippet, reason:'uploaded-quick' });
    }

    saveCookieIndex();
    return res.json({ ok:true, parsed: lines.length, totalLines: lines.length });
  } catch (e) {
    simpleLog('uploadQuick-error', e && e.message);
    return res.status(500).json({ ok:false, error: e && e.message ? e.message : String(e) });
  }
});

// start runner
app.post('/start', requireAdmin, (req, res) => {
  const body = req.body || {};
  const sessionId = body.sessionId || 'default';
  const sess = getSession(sessionId);
  if (sess.running) return res.status(409).json({ ok:false, message:'Job already running' });
  if (!body.targetUrl && !body.target) return res.status(400).json({ ok:false, message:'targetUrl required' });

  (async () => {
    try { await reportRunner(sessionId, body); } catch(e) { sseSend(sessionId,'fatal',{msg:e && e.message? e.message:String(e)}); }
  })();

  res.json({ ok:true, message:'Job started', sessionId });
});

// stop runner
app.post('/stop', requireAdmin, async (req, res) => {
  const sessionId = req.body.sessionId || 'default';
  const sess = getSession(sessionId);
  if (!sess.running) {
    // still clear preview intervals to be safe
    clearAllPreviewIntervals(sessionId);
    return res.json({ ok:false, message:'No active job' });
  }
  sess.abort = true;
  sseSend(sessionId,'info',{msg:'Stop requested by user'});
  try {
    // close pages & contexts
    for (const p of sess.pages) { try { await p.close(); } catch(e) {} }
    sess.pages = [];
    for (const c of sess.contexts) { try { await c.close(); } catch(e) {} }
    sess.contexts = [];
    // close browser
    if (sess.browser) { try { await sess.browser.close(); } catch(e) {} sess.browser = null; }
    // clear any preview intervals
    clearAllPreviewIntervals(sessionId);
  } catch (e) { simpleLog('stop-cleanup-error', e && e.message); }
  return res.json({ ok:true, message:'Stop requested and cleanup attempted' });
});

// clear logs (session)
app.post('/clearLogs', requireAdmin, (req,res) => {
  const sid = req.body.sessionId || 'default';
  const sess = getSession(sid);
  sess.logs = [];
  res.json({ ok:true });
});

// status
app.get('/status', requireAdmin, (req,res) => {
  const sessionId = req.query.sessionId || 'default';
  const sess = getSession(sessionId);
  res.json({ running: sess.running, abort: sess.abort, logs: sess.logs.slice(-200) });
});

// example cookies
app.get('/exampleCookies', (req,res) => {
  res.type('text/plain').send('fr=...; xs=...; c_user=1000...; datr=...; sb=...; wd=390x844;');
});

// error handler
app.use((err, req, res, next) => {
  console.error('Uncaught server error:', err);
  simpleLog('uncaught-server-error', err && err.message ? err.message : String(err));
  try { res.status(500).json({ ok:false, message: err.message || 'Server error' }); } catch(e) {}
});

// unhandled handlers
process.on('unhandledRejection', (reason) => { console.error('Unhandled Rejection:', reason); simpleLog('unhandledRejection', String(reason)); });
process.on('uncaughtException', (err) => { console.error('Uncaught Exception:', err); simpleLog('uncaughtException', err && err.stack || String(err)); setTimeout(()=>process.exit(1),5000); });

// graceful
async function gracefulShutdown() {
  simpleLog('Graceful shutdown initiated');
  for (const [sid, sess] of sessions.entries()) {
    try {
      sess.abort = true;
      for (const p of sess.pages) { try { await p.close(); } catch(e) {} }
      for (const c of sess.contexts) { try { await c.close(); } catch(e) {} }
      if (sess.browser) { try { await sess.browser.close(); } catch(e) {} }
      // clear preview intervals too
      clearAllPreviewIntervals(sid);
    } catch (e) {}
  }
  process.exit(0);
}
process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);

// start server
app.listen(PORT, () => {
  simpleLog(`🚀 Server listening on port ${PORT}`);
});
