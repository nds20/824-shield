/*
 * 824 Shield — defense against AI-driven attacks.
 * Copyright (C) 2026 Nicholas Smith / 824
 *
 * This file is part of 824 Shield, free software licensed under the
 * GNU General Public License v3.0 (see the LICENSE file).
 */

// SIEM export: stream Shield decisions into the security tooling
// that hospitals, utilities, municipalities, and enterprises already
// run. A detection only defends anyone if somebody's console sees
// it — these formatters turn every decision into a line a SOC can
// ingest (CEF for ArcSight/Splunk-style pipelines, RFC 5424 syslog,
// or newline-delimited JSON for everything else).
//
//   import { Shield, siemAudit } from '824-shield';
//   const shield = new Shield({
//     onDecision: siemAudit({ format: 'cef', sink: (line) => send(line) }),
//   });

const CEF_VENDOR = '824';
const CEF_PRODUCT = 'Shield';
const CEF_VERSION = '0.5.0';

function cefEscape(value) {
  return String(value ?? '').replace(/\\/g, '\\\\').replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
}

function cefExtensionEscape(value) {
  return String(value ?? '').replace(/\\/g, '\\\\').replace(/=/g, '\\=').replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
}

// Map a Shield action to a CEF severity (0-10 scale).
function cefSeverity(action) {
  if (action === 'block') return 8;
  if (action === 'challenge') return 5;
  return 1;
}

// One decision as an ArcSight CEF line.
export function formatDecisionCEF(decision) {
  const signature = decision.reasons?.length ? 'shield-decision' : 'shield-allow';
  const name = `824 Shield ${decision.action}`;
  const extensions = [
    `src=${cefExtensionEscape(decision.ip)}`,
    `requestMethod=${cefExtensionEscape(decision.method)}`,
    `request=${cefExtensionEscape(decision.path)}`,
    `act=${cefExtensionEscape(decision.action)}`,
    `msg=${cefExtensionEscape((decision.reasons || []).join('; '))}`,
    `cs1=${cefExtensionEscape(JSON.stringify(decision.scores || {}))}`,
    'cs1Label=scores',
  ].join(' ');
  return [
    `CEF:0|${CEF_VENDOR}|${CEF_PRODUCT}|${CEF_VERSION}|${signature}|${name}|${cefSeverity(decision.action)}|${extensions}`,
  ].join('');
}

// One decision as an RFC 5424 syslog line (structured data carries
// the machine-readable payload).
export function formatDecisionSyslog(decision, { hostname = 'shield', appName = '824-shield' } = {}) {
  const ts = decision.at || new Date().toISOString();
  const sd = JSON.stringify(decision).replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\]/g, '\\]');
  return `<134>1 ${ts} ${hostname} ${appName} - - [shield@824 decision="${sd}"] 824 Shield ${decision.action} ${decision.method} ${decision.path} from ${decision.ip}`;
}

// One decision as a JSON line (NDJSON — one event per line).
export function formatDecisionJSON(decision) {
  return JSON.stringify({ source: '824-shield', ...decision });
}

const FORMATTERS = { cef: formatDecisionCEF, syslog: formatDecisionSyslog, json: formatDecisionJSON };

// Build an onDecision callback that formats each decision and hands
// the line to your sink (a log shipper, a fetch to your collector,
// a console). Defaults to JSON lines on console.log.
export function siemAudit({ format = 'json', sink = (line) => console.log(line), onlyFlagged = false } = {}) {
  const formatter = FORMATTERS[format] || FORMATTERS.json;
  return (decision) => {
    if (onlyFlagged && decision.action === 'allow') return;
    sink(formatter(decision));
  };
}
