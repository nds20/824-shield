/*
 * 824 Shield — defense against AI-driven attacks.
 * Copyright (C) 2026 Nicholas Smith / 824
 *
 * This file is part of 824 Shield, free software licensed under the
 * GNU General Public License v3.0 (see the LICENSE file).
 */

// Shield Proxy — a zero-dependency reverse proxy that puts 824
// Shield in front of ANY application, in any language: WordPress
// and PHP sites, Java/.NET services, legacy apps you cannot or
// should not modify. Deploy it on a VPS, in Docker, or as a
// Kubernetes sidecar — if it speaks HTTP, Shield can stand in
// front of it.
//
//   UPSTREAM=http://127.0.0.1:8080 PORT=8787 node apps/shield-proxy.js
//
// Notes for production: response bodies are buffered (fine for
// typical app traffic; very large downloads should bypass the
// proxy), and TLS should terminate at your load balancer or a
// fronting server (Caddy/nginx/Cloudflare) as usual.

import http from 'node:http';
import { fileURLToPath } from 'node:url';
import { Shield } from '../src/index.js';
import { securityHeaders } from '../src/headers.js';

const MAX_BODY_BYTES = 10 * 1024 * 1024;

export function createShieldProxy({ upstream, shield }) {
  const secHeaders = securityHeaders();
  const upstreamBase = upstream.replace(/\/$/, '');

  return http.createServer(async (req, res) => {
    const chunks = [];
    let total = 0;
    for await (const chunk of req) {
      total += chunk.length;
      if (total > MAX_BODY_BYTES) {
        res.writeHead(413, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Payload too large.' }));
        return;
      }
      chunks.push(chunk);
    }
    const body = Buffer.concat(chunks);

    const contentType = req.headers['content-type'] || '';
    const bodyText = ['POST', 'PUT', 'PATCH'].includes(req.method) && !contentType.includes('multipart/form-data')
      ? body.toString('utf8')
      : '';
    const decision = shield.evaluate({
      ip: (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || 'unknown',
      method: req.method,
      path: (req.url || '/').split('?')[0],
      headers: req.headers,
      bodyText,
    });

    if (decision.action === 'block') {
      res.writeHead(403, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Request blocked by 824 Shield.', reasons: decision.reasons }));
      return;
    }

    const forwardHeaders = { ...req.headers };
    delete forwardHeaders.host;
    delete forwardHeaders.connection;
    delete forwardHeaders['content-length'];

    let upstreamRes;
    try {
      upstreamRes = await fetch(upstreamBase + req.url, {
        method: req.method,
        headers: forwardHeaders,
        body: ['GET', 'HEAD'].includes(req.method) ? undefined : body,
        redirect: 'manual',
      });
    } catch {
      res.writeHead(502, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Upstream unavailable.' }));
      return;
    }

    const responseHeaders = {};
    upstreamRes.headers.forEach((value, key) => {
      if (!['transfer-encoding', 'connection', 'content-length'].includes(key)) responseHeaders[key] = value;
    });
    for (const [name, value] of Object.entries(secHeaders)) {
      if (!upstreamRes.headers.has(name)) responseHeaders[name] = value;
    }
    if (decision.action === 'challenge') responseHeaders['X-824-Shield'] = 'challenge';

    const responseBody = Buffer.from(await upstreamRes.arrayBuffer());
    res.writeHead(upstreamRes.status, responseHeaders);
    res.end(responseBody);
  });
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  const upstream = process.env.UPSTREAM;
  if (!upstream) {
    console.error('Set UPSTREAM, e.g. UPSTREAM=http://127.0.0.1:8080 node apps/shield-proxy.js');
    process.exit(1);
  }
  const port = Number(process.env.PORT || 8787);
  const shield = new Shield({
    onDecision: (d) => { if (d.action !== 'allow') console.warn('[824-shield]', JSON.stringify(d)); },
  });
  createShieldProxy({ upstream, shield }).listen(port, () => {
    console.log(`824 Shield proxy listening on :${port}, guarding ${upstream}`);
  });
}
