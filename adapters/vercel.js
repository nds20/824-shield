/*
 * 824 Shield — defense against AI-driven attacks.
 * Copyright (C) 2026 Nicholas Smith / 824
 *
 * This file is part of 824 Shield, free software licensed under the
 * GNU General Public License v3.0 (see the LICENSE file).
 */

// Vercel adapter — for Edge-runtime route handlers and functions
// (web-standard Request/Response):
//
//   import { Shield } from '../src/index.js';
//   import { withShieldVercel } from './adapters/vercel.js';
//   const shield = new Shield();
//   export const GET = withShieldVercel(myGET, shield);
//
// Node-runtime Vercel functions using (req, res) can use the Google
// Cloud Functions adapter shape instead (same signature).

import { withShieldFetch, forwardedForIp } from './fetch.js';

export function withShieldVercel(handler, shield) {
  return withShieldFetch(handler, shield, forwardedForIp);
}
