/*
 * 824 Shield — defense against AI-driven attacks.
 * Copyright (C) 2026 Nicholas Smith / 824
 *
 * This file is part of 824 Shield, free software licensed under the
 * GNU General Public License v3.0 (see the LICENSE file).
 */

// Fastly Compute adapter — fetch-style handlers; Fastly stamps the
// client address in the Fastly-Client-IP header:
//
//   import { Shield } from '../src/index.js';
//   import { withShieldFastly } from './adapters/fastly.js';
//   const shield = new Shield();
//   addEventListener('fetch', (event) =>
//     event.respondWith(withShieldFastly(handler, shield)(event.request)));

import { withShieldFetch, forwardedForIp } from './fetch.js';

export function withShieldFastly(handler, shield) {
  return withShieldFetch(handler, shield, (request) =>
    request.headers.get('fastly-client-ip') || forwardedForIp(request));
}
