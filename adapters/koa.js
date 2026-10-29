/*
 * 824 Shield — defense against AI-driven attacks.
 * Copyright (C) 2026 Nicholas Smith / 824
 *
 * This file is part of 824 Shield, free software licensed under the
 * GNU General Public License v3.0 (see the LICENSE file).
 */

// Koa adapter — mount AFTER your body parser so request bodies are
// available for scanning:
//
//   import { Shield } from '../src/index.js';
//   import { shieldKoa } from './adapters/koa.js';
//   app.use(bodyParser());
//   app.use(shieldKoa(new Shield()));

import { securityHeaders } from '../src/headers.js';

export function shieldKoa(shield) {
  return async (ctx, next) => {
    const contentType = ctx.get('content-type') || '';
    const rawBody = ctx.request.body;
    const bodyText = !contentType.includes('multipart/form-data') && rawBody != null
      ? (typeof rawBody === 'string' ? rawBody : JSON.stringify(rawBody))
      : '';
    const decision = shield.evaluate({
      ip: ctx.ip || 'unknown',
      method: ctx.method,
      path: ctx.path || '/',
      headers: ctx.headers || {},
      bodyText,
    });
    if (decision.action === 'block') {
      ctx.status = 403;
      ctx.body = { error: 'Request blocked by 824 Shield.', reasons: decision.reasons };
      return;
    }
    await next();
    for (const [name, value] of Object.entries(securityHeaders())) {
      if (!ctx.response.get(name)) ctx.set(name, value);
    }
    if (decision.action === 'challenge') ctx.set('X-824-Shield', 'challenge');
  };
}
