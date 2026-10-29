/*
 * 824 Shield — defense against AI-driven attacks.
 * Copyright (C) 2026 Nicholas Smith / 824
 *
 * This file is part of 824 Shield, free software licensed under the
 * GNU General Public License v3.0 (see the LICENSE file).
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { formatDecisionCEF, formatDecisionSyslog, formatDecisionJSON, siemAudit } from '../src/siem.js';

const DECISION = {
  action: 'block',
  ip: '198.51.100.7',
  method: 'POST',
  path: '/api/login',
  scores: { bot: 0, injection: 0, exploit: 65 },
  reasons: ['Cyber-exploit signal: SQL injection: always-true condition'],
  at: '2026-10-29T06:00:00.000Z',
};

test('CEF line carries vendor, severity, and the decision fields', () => {
  const line = formatDecisionCEF(DECISION);
  assert.match(line, /^CEF:0\|824\|Shield\|/);
  assert.ok(line.includes('|8|'), 'block severity should be 8');
  assert.ok(line.includes('src=198.51.100.7'));
  assert.ok(line.includes('act=block'));
});

test('CEF escapes pipes and newlines in reasons', () => {
  const line = formatDecisionCEF({ ...DECISION, reasons: ['a|b\nc'] });
  assert.ok(!line.includes('a|b'));
  assert.ok(line.includes('a\\|b'));
});

test('syslog line is RFC 5424 shaped with structured data', () => {
  const line = formatDecisionSyslog(DECISION, { hostname: 'hospital-gateway' });
  assert.match(line, /^<134>1 2026-10-29T06:00:00\.000Z hospital-gateway 824-shield - - \[shield@824 /);
  assert.ok(line.includes('824 Shield block POST /api/login from 198.51.100.7'));
});

test('JSON formatter round-trips the decision', () => {
  const parsed = JSON.parse(formatDecisionJSON(DECISION));
  assert.equal(parsed.source, '824-shield');
  assert.equal(parsed.action, 'block');
  assert.equal(parsed.scores.exploit, 65);
});

test('siemAudit only emits flagged decisions when asked', () => {
  const lines = [];
  const audit = siemAudit({ format: 'json', sink: (l) => lines.push(l), onlyFlagged: true });
  audit({ ...DECISION, action: 'allow', reasons: [] });
  audit(DECISION);
  assert.equal(lines.length, 1);
  assert.equal(JSON.parse(lines[0]).action, 'block');
});
