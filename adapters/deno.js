/*
 * 824 Shield — defense against AI-driven attacks.
 * Copyright (C) 2026 Nicholas Smith / 824
 *
 * This file is part of 824 Shield, free software licensed under the
 * GNU General Public License v3.0 (see the LICENSE file).
 */

// Deno Deploy / Deno.serve adapter — handler signature (request,
// info), client address at info.remoteAddr.hostname. The same
// wrapper also fits Supabase Edge Functions (wrap your serve
// handler; IP falls back to x-forwarded-for there):
//
//   import { Shield } from '../src/index.js';
//   import { withShieldDeno } from './adapters/deno.js';
//   const shield = new Shield();
//   Deno.serve(withShieldDeno(handler, shield));

import { withShieldFetch, forwardedForIp } from './fetch.js';

export function withShieldDeno(handler, shield) {
  return withShieldFetch(handler, shield, (request, info) =>
    info?.remoteAddr?.hostname || forwardedForIp(request));
}
