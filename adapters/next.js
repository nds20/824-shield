/*
 * 824 Shield — defense against AI-driven attacks.
 * Copyright (C) 2026 Nicholas Smith / 824
 *
 * This file is part of 824 Shield, free software licensed under the
 * GNU General Public License v3.0 (see the LICENSE file).
 */

// Next.js adapter — for App Router route handlers (app/api/**/route.ts),
// which use web-standard Request/Response:
//
//   import { Shield } from '../../src/index.js';
//   import { withShieldNext } from '824-shield/next';
//   const shield = new Shield();
//   export const POST = withShieldNext(myPOST, shield);
//
// For protecting pages as well as APIs, the same wrapper works in
// middleware.ts around a fetch-style handler.

import { withShieldFetch, forwardedForIp } from './fetch.js';

export function withShieldNext(handler, shield) {
  return withShieldFetch(handler, shield, forwardedForIp);
}
