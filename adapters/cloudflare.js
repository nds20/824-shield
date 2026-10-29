/*
 * 824 Shield — defense against AI-driven attacks.
 * Copyright (C) 2026 Nicholas Smith / 824
 *
 * This file is part of 824 Shield, free software licensed under the
 * GNU General Public License v3.0 (see the LICENSE file).
 */

// Cloudflare Worker adapter — wrap your fetch handler:
//
//   import { Shield } from '../src/index.js';
//   import { withShield } from './adapters/cloudflare.js';
//
//   const shield = new Shield();
//   export default { fetch: withShield(myHandler, shield) };
//
// Note: the default in-memory stores live as long as the Worker isolate
// does. For hard cross-request limits in production, back the Shield
// with KV / Durable Objects, or pair it with Cloudflare rate-limit
// rules — see "Honest limits" in the README.

import { applySecurityHeaders } from '../src/headers.js';

export function withShield(handler, shield) {
  return async (request, env, ctx) => {
    let bodyText = '';
    if (['POST', 'PUT', 'PATCH'].includes(request.method)) {
      try { bodyText = await request.clone().text(); } catch { bodyText = ''; }
    }
    const headers = {};
    request.headers.forEach((value, key) => { headers[key] = value; });

    const decision = shield.evaluate({
      ip: request.headers.get('CF-Connecting-IP') || 'unknown',
      method: request.method,
      path: new URL(request.url).pathname,
      headers,
      bodyText,
    });

    if (decision.action === 'block') {
      return new Response(
        JSON.stringify({ error: 'Request blocked by 824 Shield.', reasons: decision.reasons }),
        { status: 403, headers: { 'Content-Type': 'application/json' } },
      );
    }

    const response = await handler(request, env, ctx);
    if (decision.action === 'challenge') {
      const flagged = new Response(response.body, response);
      flagged.headers.set('X-824-Shield', 'challenge');
      return applySecurityHeaders(flagged);
    }
    return applySecurityHeaders(response);
  };
}
