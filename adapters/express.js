/*
 * 824 Shield — defense against AI-driven attacks.
 * Copyright (C) 2026 Nicholas Smith / 824
 *
 * This file is part of 824 Shield, free software licensed under the
 * GNU General Public License v3.0 (see the LICENSE file).
 */

// Express adapter.
//
//   import express from 'express';
//   import { Shield } from '../src/index.js';
//   import { shieldMiddleware, loginGate } from './adapters/express.js';
//
//   const shield = new Shield();
//   app.use(shieldMiddleware(shield));            // every request
//   app.post('/login', loginGate(shield), login); // plus the stuffing gate
//
// In your login handler, call shield.recordLoginFailure(ip, email) on a
// bad password and shield.recordLoginSuccess(ip, email) on success.

export function shieldMiddleware(shield) {
  return (req, res, next) => {
    const bodyText = req.body
      ? (typeof req.body === 'string' ? req.body : JSON.stringify(req.body))
      : '';
    const decision = shield.evaluate({
      ip: req.ip,
      method: req.method,
      path: req.path || req.url,
      headers: req.headers || {},
      bodyText,
    });
    if (decision.action === 'block') {
      return res.status(403).json({ error: 'Request blocked by 824 Shield.', reasons: decision.reasons });
    }
    if (decision.action === 'challenge') res.setHeader('X-824-Shield', 'challenge');
    return next();
  };
}

export function loginGate(shield) {
  return (req, res, next) => {
    const account = req.body?.email || req.body?.username;
    const lock = shield.loginLocked(req.ip, account);
    if (lock.locked) {
      return res.status(429).json({
        error: 'Too many failed sign-in attempts. Try again later.',
        retryAfterSeconds: Math.ceil(lock.retryAfterMs / 1000),
      });
    }
    return next();
  };
}
