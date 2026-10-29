/*
 * 824 Shield — defense against AI-driven attacks.
 * Copyright (C) 2026 Nicholas Smith / 824
 *
 * This file is part of 824 Shield, free software licensed under the
 * GNU General Public License v3.0 (see the LICENSE file).
 */

// Generic web-standard fetch wrapper — the shared core for every
// edge/fetch platform (Vercel, Netlify, Deno, Bun, Fastly, Next.js,
// Supabase Edge, and friends). Platform adapters in this folder are
// thin presets over this function; the only real difference between
// platforms is where the client IP lives.
//
// getIp(request, extra) => string — `extra` is whatever the platform
// passes alongside the request (Netlify context, Deno conn info,
// Bun server, ...).

import { applySecurityHeaders } from '../src/headers.js';

export function withShieldFetch(handler, shield, getIp) {
  return async (request, ...rest) => {
    const contentType = request.headers.get('content-type') || '';
    let bodyText = '';
    if (['POST', 'PUT', 'PATCH'].includes(request.method) && !contentType.includes('multipart/form-data')) {
      try { bodyText = await request.clone().text(); } catch { bodyText = ''; }
    }
    const headers = {};
    request.headers.forEach((value, key) => { headers[key] = value; });

    const decision = shield.evaluate({
      ip: (typeof getIp === 'function' && getIp(request, ...rest)) || 'unknown',
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

    const response = await handler(request, ...rest);
    if (!(response instanceof Response)) return response;
    if (decision.action === 'challenge') {
      const flagged = new Response(response.body, response);
      flagged.headers.set('X-824-Shield', 'challenge');
      return applySecurityHeaders(flagged);
    }
    return applySecurityHeaders(response);
  };
}

// The most common IP source across proxies and platforms.
export function forwardedForIp(request) {
  const forwarded = (request.headers.get('x-forwarded-for') || '').split(',')[0].trim();
  return forwarded || request.headers.get('x-real-ip') || 'unknown';
}
