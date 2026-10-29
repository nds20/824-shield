/*
 * 824 Shield — defense against AI-driven attacks.
 * Copyright (C) 2026 Nicholas Smith / 824
 *
 * This file is part of 824 Shield, free software licensed under the
 * GNU General Public License v3.0 (see the LICENSE file).
 */

// AWS Lambda adapter — protect APIs fronted by API Gateway (REST or
// HTTP API) or an ALB. Wrap your handler:
//
//   import { Shield } from '../src/index.js';
//   import { withShieldLambda } from './adapters/aws-lambda.js';
//
//   const shield = new Shield();
//   export const handler = withShieldLambda(myHandler, shield);
//
// Handles payload format 1.0 (REST API / ALB) and 2.0 (HTTP API),
// including base64-encoded request bodies. Blocked requests never
// reach your handler. Defensive headers are added to every response
// your handler returns (headers it set itself win).
//
// Note: Lambda's in-memory stores live as long as the execution
// environment does — fine for burst protection; pair with API
// Gateway usage plans / AWS WAF for hard account-level limits.

import { securityHeaders } from '../src/headers.js';

function lowerHeaders(headers = {}) {
  const out = {};
  for (const [key, value] of Object.entries(headers)) out[key.toLowerCase()] = value;
  return out;
}

function eventContext(event) {
  const isV2 = event.version === '2.0';
  const headers = lowerHeaders(event.headers);
  let bodyText = '';
  if (event.body) {
    bodyText = event.isBase64Encoded
      ? Buffer.from(event.body, 'base64').toString('utf8')
      : event.body;
  }
  // Multipart uploads are never payload-scanned (large, binary).
  if ((headers['content-type'] || '').includes('multipart/form-data')) bodyText = '';
  return {
    isV2,
    ctx: {
      ip: isV2
        ? event.requestContext?.http?.sourceIp || 'unknown'
        : event.requestContext?.identity?.sourceIp || 'unknown',
      method: isV2 ? event.requestContext?.http?.method || 'GET' : event.httpMethod || 'GET',
      path: isV2 ? event.requestContext?.http?.path || '/' : event.path || '/',
      headers,
      bodyText,
    },
  };
}

function blockedResponse(decision, isV2) {
  const body = JSON.stringify({ error: 'Request blocked by 824 Shield.', reasons: decision.reasons });
  const headers = { 'Content-Type': 'application/json', ...securityHeaders() };
  if (isV2) return { statusCode: 403, headers, body };
  return { statusCode: 403, headers, body, isBase64Encoded: false };
}

export function withShieldLambda(handler, shield) {
  return async (event, context) => {
    const { isV2, ctx } = eventContext(event || {});
    const decision = shield.evaluate(ctx);
    if (decision.action === 'block') return blockedResponse(decision, isV2);

    const response = await handler(event, context);
    if (!response || typeof response !== 'object') return response;
    const headers = { ...(response.headers || {}) };
    for (const [name, value] of Object.entries(securityHeaders())) {
      const existing = Object.keys(headers).find((k) => k.toLowerCase() === name.toLowerCase());
      if (!existing) headers[name] = value;
    }
    if (decision.action === 'challenge') headers['X-824-Shield'] = 'challenge';
    return { ...response, headers };
  };
}
