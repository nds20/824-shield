/*
 * 824 Shield — defense against AI-driven attacks.
 * Copyright (C) 2026 Nicholas Smith / 824
 *
 * This file is part of 824 Shield, free software licensed under the
 * GNU General Public License v3.0 (see the LICENSE file).
 */

// Bun adapter — for Bun.serve fetch handlers, where the server
// object can resolve the client address via server.requestIP():
//
//   import { Shield } from '../src/index.js';
//   import { withShieldBun } from './adapters/bun.js';
//   const shield = new Shield();
//   Bun.serve({ fetch: withShieldBun(handler, shield) });

import { withShieldFetch, forwardedForIp } from './fetch.js';

export function withShieldBun(handler, shield) {
  return withShieldFetch(handler, shield, (request, server) => {
    try { return server?.requestIP?.(request)?.address || forwardedForIp(request); }
    catch { return forwardedForIp(request); }
  });
}
