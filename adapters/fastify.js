/*
 * 824 Shield — defense against AI-driven attacks.
 * Copyright (C) 2026 Nicholas Smith / 824
 *
 * This file is part of 824 Shield, free software licensed under the
 * GNU General Public License v3.0 (see the LICENSE file).
 */

// Fastify adapter — register as a plugin; Shield evaluates in the
// preValidation hook (after body parsing, before your handler) and
// stamps defensive headers onSend:
//
//   import { Shield } from '../src/index.js';
//   import { shieldFastify } from './adapters/fastify.js';
//   await fastify.register(shieldFastify, { shield: new Shield() });

import { securityHeaders } from '../src/headers.js';

export async function shieldFastify(fastify, options = {}) {
  const shield = options.shield || (() => { throw new Error('shieldFastify requires { shield }'); })();

  fastify.addHook('preValidation', async (request, reply) => {
    const contentType = request.headers['content-type'] || '';
    const bodyText = !contentType.includes('multipart/form-data') && request.body != null
      ? (typeof request.body === 'string' ? request.body : JSON.stringify(request.body))
      : '';
    const decision = shield.evaluate({
      ip: request.ip || 'unknown',
      method: request.method,
      path: (request.url || '/').split('?')[0],
      headers: request.headers || {},
      bodyText,
    });
    request.shieldDecision = decision;
    if (decision.action === 'block') {
      reply.code(403).send({ error: 'Request blocked by 824 Shield.', reasons: decision.reasons });
    }
  });

  fastify.addHook('onSend', async (request, reply, payload) => {
    for (const [name, value] of Object.entries(securityHeaders())) {
      if (!reply.hasHeader(name)) reply.header(name, value);
    }
    if (request.shieldDecision?.action === 'challenge') reply.header('X-824-Shield', 'challenge');
    return payload;
  });
}
