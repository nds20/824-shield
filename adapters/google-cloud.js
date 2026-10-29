/*
 * 824 Shield — defense against AI-driven attacks.
 * Copyright (C) 2026 Nicholas Smith / 824
 *
 * This file is part of 824 Shield, free software licensed under the
 * GNU General Public License v3.0 (see the LICENSE file).
 */

// Google Cloud Functions adapter — GCF (and Firebase Functions) use
// the Express-style (req, res) signature. Wrap your function:
//
//   import { Shield } from '../src/index.js';
//   import { withShieldGcf } from './adapters/google-cloud.js';
//   export const api = withShieldGcf(myHandler, new Shield());
//
// Pair with Cloud Armor in front for network-layer protection.
// Cloud Run services running a full framework should use that
// framework's adapter (Express / Fastify / Koa / Hono) instead.

import { securityHeaders } from '../src/headers.js';

export function withShieldGcf(handler, shield) {
  return (req, res) => {
    const contentType = req.headers?.['content-type'] || '';
    let bodyText = '';
    if (!contentType.includes('multipart/form-data')) {
      if (typeof req.body === 'string') bodyText = req.body;
      else if (Buffer.isBuffer(req.body)) bodyText = req.body.toString('utf8');
      else if (req.body && typeof req.body === 'object') bodyText = JSON.stringify(req.body);
      else if (typeof req.rawBody === 'string') bodyText = req.rawBody;
    }
    const decision = shield.evaluate({
      ip: (req.headers?.['x-forwarded-for'] || '').split(',')[0].trim() || req.ip || 'unknown',
      method: req.method || 'GET',
      path: (req.path || req.url || '/').split('?')[0],
      headers: req.headers || {},
      bodyText,
    });
    if (decision.action === 'block') {
      return res.status(403).json({ error: 'Request blocked by 824 Shield.', reasons: decision.reasons });
    }
    for (const [name, value] of Object.entries(securityHeaders())) res.set(name, value);
    if (decision.action === 'challenge') res.set('X-824-Shield', 'challenge');
    return handler(req, res);
  };
}
