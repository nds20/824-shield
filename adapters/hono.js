/*
 * 824 Shield — defense against AI-driven attacks.
 * Copyright (C) 2026 Nicholas Smith / 824
 *
 * This file is part of 824 Shield, free software licensed under the
 * GNU General Public License v3.0 (see the LICENSE file).
 */

// Hono adapter — Hono runs on Workers, Bun, Deno, and Node, so this
// one middleware covers apps on all of them:
//
//   import { Hono } from 'hono';
//   import { Shield } from '../src/index.js';
//   import { shieldHono } from './adapters/hono.js';
//   app.use(shieldHono(new Shield()));

import { securityHeaders } from '../src/headers.js';

export function shieldHono(shield) {
  return async (c, next) => {
    const req = c.req;
    const contentType = req.header('content-type') || '';
    let bodyText = '';
    if (['POST', 'PUT', 'PATCH'].includes(req.method) && !contentType.includes('multipart/form-data')) {
      try { bodyText = await req.text(); } catch { bodyText = ''; }
    }
    const decision = shield.evaluate({
      ip: req.header('cf-connecting-ip') || (req.header('x-forwarded-for') || '').split(',')[0].trim() || 'unknown',
      method: req.method,
      path: new URL(req.url).pathname,
      headers: Object.fromEntries(new Headers(req.raw.headers)),
      bodyText,
    });
    if (decision.action === 'block') {
      return c.json({ error: 'Request blocked by 824 Shield.', reasons: decision.reasons }, 403);
    }
    await next();
    for (const [name, value] of Object.entries(securityHeaders())) {
      if (!c.res.headers.has(name)) c.header(name, value);
    }
    if (decision.action === 'challenge') c.header('X-824-Shield', 'challenge');
    return undefined;
  };
}
