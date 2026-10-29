/*
 * 824 Shield — defense against AI-driven attacks.
 * Copyright (C) 2026 Nicholas Smith / 824
 *
 * This file is part of 824 Shield, free software licensed under the
 * GNU General Public License v3.0 (see the LICENSE file).
 */

// Azure Functions adapter — Node.js v4 programming model, which uses
// web-standard Request/Response objects just like fetch. Wrap your
// HTTP function:
//
//   import { app } from '@azure/functions';
//   import { Shield } from '../src/index.js';
//   import { withShieldAzure } from './adapters/azure-functions.js';
//
//   const shield = new Shield();
//   app.http('api', { handler: withShieldAzure(myHandler, shield) });
//
// Client IP comes from x-forwarded-for (set by Azure Front Door /
// App Gateway / the Functions host behind them); the first hop is
// the client. Handlers should return standard Response objects —
// non-Response results pass through untouched. For classic (v3)
// functions or Express apps hosted on App Service, use the Express
// adapter instead.

import { applySecurityHeaders } from '../src/headers.js';

export function withShieldAzure(handler, shield) {
  return async (request, context) => {
    const contentType = request.headers.get('content-type') || '';
    let bodyText = '';
    if (['POST', 'PUT', 'PATCH'].includes(request.method) && !contentType.includes('multipart/form-data')) {
      try { bodyText = await request.clone().text(); } catch { bodyText = ''; }
    }
    const headers = {};
    request.headers.forEach((value, key) => { headers[key] = value; });
    const forwarded = (headers['x-forwarded-for'] || '').split(',')[0].trim();

    const decision = shield.evaluate({
      ip: forwarded || 'unknown',
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

    const response = await handler(request, context);
    if (!(response instanceof Response)) return response;
    if (decision.action === 'challenge') {
      const flagged = new Response(response.body, response);
      flagged.headers.set('X-824-Shield', 'challenge');
      return applySecurityHeaders(flagged);
    }
    return applySecurityHeaders(response);
  };
}
