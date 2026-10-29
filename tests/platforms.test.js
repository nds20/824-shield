/*
 * 824 Shield — defense against AI-driven attacks.
 * Copyright (C) 2026 Nicholas Smith / 824
 *
 * This file is part of 824 Shield, free software licensed under the
 * GNU General Public License v3.0 (see the LICENSE file).
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { Shield } from '../src/index.js';
import { withShieldVercel } from '../adapters/vercel.js';
import { withShieldNetlify } from '../adapters/netlify.js';
import { withShieldDeno } from '../adapters/deno.js';
import { withShieldBun } from '../adapters/bun.js';
import { withShieldFastly } from '../adapters/fastly.js';
import { withShieldNext } from '../adapters/next.js';
import { shieldHono } from '../adapters/hono.js';
import { shieldFastify } from '../adapters/fastify.js';
import { shieldKoa } from '../adapters/koa.js';
import { withShieldGcf } from '../adapters/google-cloud.js';
import { createShieldProxy } from '../apps/shield-proxy.js';

const BROWSER = {
  'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36',
  'accept': 'application/json',
  'accept-language': 'en-US,en;q=0.9',
  'accept-encoding': 'gzip, deflate, br',
  'sec-fetch-site': 'same-origin',
  'x-forwarded-for': '203.0.113.10',
};
const fetchOk = async () => new Response(JSON.stringify({ ok: true }), { headers: { 'Content-Type': 'application/json' } });
const get = (url, headers = BROWSER) => new Request(url, { headers });
const post = (url, body) => new Request(url, {
  method: 'POST', headers: { ...BROWSER, 'content-type': 'application/json' }, body: JSON.stringify(body),
});
const SQLI = { email: "admin' OR 1=1 --", password: 'x' };

for (const [name, wrap] of [
  ['vercel', withShieldVercel], ['next', withShieldNext], ['fastly', withShieldFastly],
]) {
  test(`${name}: allows normal, blocks SQLi, adds headers`, async () => {
    const handler = wrap(fetchOk, new Shield());
    const ok = await handler(get('https://app.example/api/products'));
    assert.equal(ok.status, 200);
    assert.equal(ok.headers.get('X-Frame-Options'), 'DENY');
    const bad = await handler(post('https://app.example/api/login', SQLI));
    assert.equal(bad.status, 403);
  });
}

test('netlify: uses context.ip and blocks probes', async () => {
  const handler = withShieldNetlify(fetchOk, new Shield());
  const bad = await handler(get('https://app.example/.env'), { ip: '198.51.100.7' });
  assert.equal(bad.status, 403);
});

test('deno: uses remoteAddr when present', async () => {
  const handler = withShieldDeno(fetchOk, new Shield());
  const ok = await handler(get('https://app.example/'), { remoteAddr: { hostname: '203.0.113.10' } });
  assert.equal(ok.status, 200);
});

test('bun: uses server.requestIP when available', async () => {
  const handler = withShieldBun(fetchOk, new Shield());
  const server = { requestIP: () => ({ address: '203.0.113.10' }) };
  const ok = await handler(get('https://app.example/'), server);
  assert.equal(ok.status, 200);
  const bad = await handler(post('https://app.example/api/login', SQLI), server);
  assert.equal(bad.status, 403);
});

test('hono: middleware blocks SQLi and stamps headers on pass', async () => {
  const mw = shieldHono(new Shield());
  const mkCtx = (reqInit, url) => {
    const headers = new Headers(reqInit.headers);
    const captured = {};
    return {
      req: {
        method: reqInit.method || 'GET', url,
        header: (n) => headers.get(n) || undefined,
        text: async () => reqInit.body || '',
        raw: { headers },
      },
      res: { headers: new Headers() },
      header: (n, v) => { captured[n] = v; },
      json: (obj, status) => ({ obj, status }),
      captured,
    };
  };
  const badCtx = mkCtx({ method: 'POST', headers: { ...BROWSER, 'content-type': 'application/json' }, body: JSON.stringify(SQLI) }, 'https://app.example/api/login');
  const blocked = await mw(badCtx, async () => {});
  assert.equal(blocked.status, 403);
  const okCtx = mkCtx({ headers: BROWSER }, 'https://app.example/api/products');
  await mw(okCtx, async () => {});
  assert.equal(okCtx.captured['X-Frame-Options'], 'DENY');
});

test('fastify: preValidation blocks SQLi, onSend adds headers', async () => {
  const hooks = {};
  const fakeFastify = { addHook: (name, fn) => { hooks[name] = fn; } };
  await shieldFastify(fakeFastify, { shield: new Shield() });
  const reply = {
    codeValue: 200, sent: null, headersSet: {},
    code(c) { this.codeValue = c; return this; },
    send(p) { this.sent = p; return this; },
    hasHeader() { return false; },
    header(n, v) { this.headersSet[n] = v; return this; },
  };
  const request = { ip: '198.51.100.7', method: 'POST', url: '/api/login', headers: { 'content-type': 'application/json', ...BROWSER }, body: SQLI };
  await hooks.preValidation(request, reply);
  assert.equal(reply.codeValue, 403);
  await hooks.onSend(request, reply, '{}');
  assert.equal(reply.headersSet['X-Frame-Options'], 'DENY');
});

test('koa: blocks SQLi with 403 body', async () => {
  const mw = shieldKoa(new Shield());
  const ctx = {
    get: () => 'application/json', ip: '198.51.100.7', method: 'POST', path: '/api/login',
    headers: { ...BROWSER }, request: { body: SQLI }, status: 200, body: null,
    response: { get: () => null }, set: () => {},
  };
  await mw(ctx, async () => { throw new Error('next must not run'); });
  assert.equal(ctx.status, 403);
});

test('google cloud functions: blocks SQLi before the handler', async () => {
  let called = false;
  const handler = withShieldGcf(() => { called = true; }, new Shield());
  const res = {
    code: 200, body: null, headersSet: {},
    status(c) { this.code = c; return this; },
    json(o) { this.body = o; return this; },
    set(n, v) { this.headersSet[n] = v; return this; },
  };
  handler({ method: 'POST', path: '/api/login', url: '/api/login', headers: { 'content-type': 'application/json', ...BROWSER }, body: SQLI, ip: '198.51.100.7' }, res);
  assert.equal(res.code, 403);
  assert.equal(called, false);
});

test('proxy: guards an upstream app end-to-end', async () => {
  let upstreamHits = 0;
  const upstream = http.createServer((req, res) => {
    upstreamHits += 1;
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true }));
  });
  await new Promise((r) => upstream.listen(0, '127.0.0.1', r));
  const proxy = createShieldProxy({ upstream: `http://127.0.0.1:${upstream.address().port}`, shield: new Shield() });
  await new Promise((r) => proxy.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${proxy.address().port}`;
  try {
    const ok = await fetch(`${base}/api/products`, { headers: BROWSER });
    assert.equal(ok.status, 200);
    assert.equal(ok.headers.get('x-frame-options'), 'DENY');
    const hitsBefore = upstreamHits;
    const bad = await fetch(`${base}/api/login`, {
      method: 'POST', headers: { ...BROWSER, 'content-type': 'application/json' }, body: JSON.stringify(SQLI),
    });
    assert.equal(bad.status, 403);
    assert.equal(upstreamHits, hitsBefore, 'blocked request must not reach upstream');
  } finally {
    proxy.close(); upstream.close();
  }
});
