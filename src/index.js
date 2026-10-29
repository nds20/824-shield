/*
 * 824 Shield — defense against AI-driven attacks.
 * Copyright (C) 2026 Nicholas Smith / 824
 *
 * This file is part of 824 Shield, free software licensed under the
 * GNU General Public License v3.0 (see the LICENSE file).
 */

export { Shield } from './guard.js';
export { scanText, normalizeForScan } from './injection.js';
export { scoreBot } from './botScore.js';
export { RateLimiter, TokenBucket } from './rateLimiter.js';
export { scanPayload, scanPath } from './exploits.js';
export { securityHeaders, applySecurityHeaders } from './headers.js';
