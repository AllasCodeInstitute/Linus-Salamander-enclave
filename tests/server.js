'use strict';
// LSES Test Dashboard — SSE Server
// Node.js built-ins only. No npm install needed.
// Usage: node tests/server.js
// Endpoints:
//   GET  /                → dashboard/index.html
//   GET  /sse             → SSE stream (shared, tests never run in parallel)
//   POST /run/:type       → execute test binary, stream to SSE
//   GET  /result/:type    → result.json for that suite
//   GET  /active          → { active: string|null, clients: number }
//   GET  /manifest/:type  → manifest.json for that suite
//   GET  /*               → static files from tests/

const http = require('http');
const fs   = require('fs');
const path = require('path');
const { spawn } = require('child_process');

const PORT = 7777;
const ROOT = __dirname; // tests/ directory

// ── MIME ──────────────────────────────────────────────────────────────────
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js':   'application/javascript; charset=utf-8',
  '.css':  'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.ico':  'image/x-icon',
  '.svg':  'image/svg+xml',
  '.png':  'image/png',
  '.woff2':'font/woff2',
};

// ── SSE state (single shared channel) ─────────────────────────────────────
const sseClients = new Set();
let activeTest   = null;

function broadcast(event, data) {
  const msg = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const res of [...sseClients]) {
    try { res.write(msg); } catch { sseClients.delete(res); }
  }
}

// ── ANSI strip ────────────────────────────────────────────────────────────
const ANSI_RE = /\x1b\[[0-9;]*[a-zA-Z]/g;
const stripAnsi = s => s.replace(ANSI_RE, '');

// ── Gherkin line parser ───────────────────────────────────────────────────
function parseGherkinLine(raw) {
  const line = stripAnsi(raw).replace(/\r/g, '').trimEnd();
  const t = line.trim();
  if (!t) return null;

  if (t.startsWith('Feature:'))  return { kind: 'feature',  text: t.slice(8).trim() };
  if (t.startsWith('Rule:'))     return { kind: 'rule',     text: t.slice(5).trim() };
  if (t.startsWith('Scenario:')) {
    const m = t.match(/^Scenario:\s*(.+?)(?:\s+\[(.+?)\])?$/);
    return { kind: 'scenario', text: m ? m[1].trim() : t.slice(9).trim(), rule: (m && m[2]) ? m[2].trim() : '' };
  }
  const stepM = t.match(/^(Given|When|Then|And|But|\*)\s+(.+)$/);
  if (stepM) return { kind: 'step', keyword: stepM[1], text: stepM[2] };

  return { kind: 'log', text: line };
}

// ── Zig test line parser ──────────────────────────────────────────────────
function parseZigTestLine(raw) {
  const line = stripAnsi(raw).replace(/\r/g, '').trimEnd();
  const t = line.trim();
  if (!t) return null;

  const m = t.match(/^\d+\/\d+\s+test[\s\."]+(.+?)["\.]*\.\.\.\s+(OK|FAIL)$/i);
  if (m) {
    return { kind: 'scenario', text: m[1].trim(), status: m[2].toLowerCase() };
  }
  return { kind: 'log', text: line };
}

// ── Test configurations ────────────────────────────────────────────────────
// Only BDD has a real binary right now. Add others when Zig/Rust binaries are ready.
const TESTS = {
  bdd: {
    exe: path.join(ROOT, 'BDD.zig', 'zig-out', 'bin', 'zig_comptime_bdd_gherkin_keyword.exe'),
    args: [],
    cwd: path.join(ROOT, 'BDD.zig'),
    parser: parseGherkinLine,
  },
  chaos: {
    exe: 'zig',
    args: ['test', 'chaos_test.zig'],
    cwd: path.join(ROOT, 'chaos'),
    parser: parseZigTestLine,
  },
};

// ── Run a test ────────────────────────────────────────────────────────────
function runTest(type, res) {
  if (activeTest) {
    res.writeHead(409, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'test_busy', active: activeTest }));
    return;
  }

  const cfg = TESTS[type];
  if (!cfg) {
    res.writeHead(501, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'no_binary', message: `"${type}" is dashboard-only (no executable configured)` }));
    return;
  }

  if (cfg.exe !== 'zig' && !fs.existsSync(cfg.exe)) {
    res.writeHead(503, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'binary_missing', path: cfg.exe, hint: 'Run: cd tests/BDD.zig && zig build' }));
    return;
  }

  activeTest = type;
  const t0 = Date.now();
  let scenarios = 0;
  let parsedScenarios = [];

  res.writeHead(202, { 'Content-Type': 'application/json' });
  broadcast('test-start', { type, ts: t0 });

  const proc = spawn(cfg.exe, cfg.args || [], { cwd: cfg.cwd, stdio: ['ignore', 'pipe', 'pipe'] });

  const onChunk = buf => {
    for (const raw of buf.toString().split('\n')) {
      const ev = cfg.parser(raw);
      if (!ev) continue;
      if (ev.kind === 'scenario') {
          scenarios++;
          parsedScenarios.push(ev);
      }
      broadcast('test-line', { ...ev, ts: Date.now() });
    }
  };

  proc.stdout.on('data', onChunk);
  proc.stderr.on('data', onChunk);

  proc.on('error', err => {
    activeTest = null;
    broadcast('test-error', { type, message: err.message });
    try { res.end(JSON.stringify({ error: err.message })); } catch {}
  });

  proc.on('close', code => {
    const duration_ms = Date.now() - t0;
    const passed = code === 0 ? scenarios : 0;
    const failed = code !== 0 ? 1 : 0;

    const result = {
      ran_at:      new Date().toISOString(),
      duration_ms,
      passed,
      failed,
      total:       scenarios,
      status:      code === 0 ? 'pass' : 'fail',
      exit_code:   code,
      scenarios:   parsedScenarios,
    };

    try { fs.writeFileSync(path.join(ROOT, type, 'result.json'), JSON.stringify(result, null, 2)); } catch {}

    activeTest = null;
    broadcast('test-done', { type, ...result });
    try { res.end(JSON.stringify({ ok: true, ...result })); } catch {}
  });
}

// ── Static file server ────────────────────────────────────────────────────
function serveFile(urlPath, res) {
  if (urlPath === '/' || urlPath === '/dashboard' || urlPath === '/dashboard/')
    urlPath = '/dashboard/index.html';
  const m = urlPath.match(/^\/(stress|unit|bdd|synk|chaos)\/?$/);
  if (m) urlPath = `/${m[1]}/index.html`;

  const abs = path.normalize(path.join(ROOT, urlPath));
  const rootSep = ROOT + path.sep;
  if (!abs.startsWith(rootSep) && abs !== ROOT) {
    res.writeHead(403); res.end('Forbidden'); return;
  }

  fs.readFile(abs, (err, data) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end(`404: ${urlPath}`);
      return;
    }
    const ext = path.extname(abs);
    res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
    res.end(data);
  });
}

// ── HTTP router ───────────────────────────────────────────────────────────
const server = http.createServer((req, res) => {
  let pathname;
  try { pathname = new URL(req.url, `http://localhost:${PORT}`).pathname; }
  catch { res.writeHead(400); res.end(); return; }

  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  // ── SSE ──
  if (pathname === '/sse') {
    res.writeHead(200, {
      'Content-Type':    'text/event-stream',
      'Cache-Control':   'no-cache',
      'Connection':      'keep-alive',
      'X-Accel-Buffering':'no',
    });
    res.write(`event: connected\ndata: ${JSON.stringify({ ts: Date.now(), active: activeTest, clients: sseClients.size + 1 })}\n\n`);

    const hb = setInterval(() => {
      try { res.write(`: hb\n\n`); }
      catch { clearInterval(hb); sseClients.delete(res); }
    }, 20000);

    sseClients.add(res);
    req.on('close', () => { clearInterval(hb); sseClients.delete(res); });
    return;
  }

  // ── Run test ──
  if (req.method === 'POST' && pathname.startsWith('/run/')) {
    runTest(pathname.slice(5), res); return;
  }

  // ── Result ──
  if (pathname.startsWith('/result/')) {
    const type = pathname.slice(8).replace(/\//g, '');
    fs.readFile(path.join(ROOT, type, 'result.json'), (err, data) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(err ? '{"status":"pending"}' : data);
    });
    return;
  }

  // ── Manifest ──
  if (pathname.startsWith('/manifest/')) {
    const type = pathname.slice(10).replace(/\//g, '');
    fs.readFile(path.join(ROOT, type, 'manifest.json'), (err, data) => {
      res.writeHead(err ? 404 : 200, { 'Content-Type': 'application/json' });
      res.end(err ? '{}' : data);
    });
    return;
  }

  // ── Active test status ──
  if (pathname === '/active') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ active: activeTest, clients: sseClients.size }));
    return;
  }

  // ── Static files ──
  serveFile(pathname, res);
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`
  ╔══════════════════════════════════════╗
  ║  LSES Test Dashboard                 ║
  ║  → http://localhost:${PORT}            ║
  ╠══════════════════════════════════════╣
  ║  /          Dashboard overview        ║
  ║  /stress    Stress & Load            ║
  ║  /unit      Unit Tests               ║
  ║  /bdd       BDD Gherkin (real exe)   ║
  ║  /synk      Sync & Concurrency       ║
  ║  /chaos     Chaos Engineering        ║
  ╚══════════════════════════════════════╝
`);
});
