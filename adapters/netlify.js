/*
 * 824 Shield — defense against AI-driven attacks.
 * Copyright (C) 2026 Nicholas Smith / 824
 *
 * This file is part of 824 Shield, free software licensed under the
 * GNU General Public License v3.0 (see the LICENSE file).
 */

// Netlify Edge Functions adapter — handler signature (request,
// context), with the real client IP provided as context.ip:
//
//   import { Shield } from '../src/index.js';
//   import { withShieldNetlify } from './adapters/netlify.js';
//   const shield = new Shield();
//   export default withShieldNetlify(myHandler, shield);

import { withShieldFetch } from './fetch.js';

export function withShieldNetlify(handler, shield) {
  return withShieldFetch(handler, shield, (request, context) => context?.ip || 'unknown');
}
