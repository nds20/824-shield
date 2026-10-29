# 824 Shield

A defense layer against **AI-driven attacks** — the automated abuse that
now targets any app with an AI feature, a login page, or an API:

| Attack | How 824 Shield answers it |
| --- | --- |
| **Prompt injection / jailbreaks** | Weighted, explainable detection of instruction-override, system-prompt extraction, role-escape, and policy-bypass language — including payloads hidden with zero-width characters, leetspeak, or base64 |
| **Credential stuffing** | A login guard that counts failures per IP *and* per account and locks the pair out (5 failures → 15-minute lockout by default) |
| **AI scrapers & bots** | Heuristic scoring of crawler / headless / scripting user-agents and browser-inconsistent headers, with an allowlist for agents you *want* |
| **API floods** | Per-IP token-bucket rate limiting with sane burst behavior |
| **SQL injection, XSS, path traversal, command injection** | A second payload scanner for the classic exploit arsenal, with percent-decoding so encoded evasions are seen clearly |
| **Log4Shell/JNDI, SSRF, XXE, NoSQL & template injection, prototype pollution, CRLF** | Dedicated rule groups, scored the same explainable way |
| **Vulnerability probing** | Requests for `/.env`, `/.git/`, `/.aws/`, wp-admin, phpMyAdmin, debug endpoints, and downloadable backups are scored as attacks, not traffic |
| **Clickjacking, MIME sniffing, XSS fallout** | One-call defensive headers (CSP, frame, sniffing, HSTS, referrer, permissions) in both adapters |

Every request gets one decision — **allow**, **challenge**, or **block** —
with human-readable reasons you can stream straight into your audit log.

Zero dependencies. Node ≥ 18. ESM.

## Quick start

```bash
npm test       # 28 attack-simulation tests
npm run demo   # watch it judge 7 live-fire scenarios
```

### Express

```js
import express from 'express';
import { Shield } from '824-shield';
import { shieldMiddleware, loginGate, headersMiddleware } from '824-shield/express';

const shield = new Shield({ onDecision: (d) => myAuditLog(d) });

const app = express();
app.use(express.json());
app.use(headersMiddleware());
app.use(shieldMiddleware(shield));
app.post('/login', loginGate(shield), (req, res) => {
  // check the password, then:
  //   shield.recordLoginFailure(req.ip, req.body.email)  on failure
  //   shield.recordLoginSuccess(req.ip, req.body.email)  on success
});
```

### Cloudflare Worker

```js
import { Shield } from '824-shield';
import { withShield } from '824-shield/cloudflare';

const shield = new Shield();
export default { fetch: withShield(myHandler, shield) };
```

## How scoring works

- **Injection scan** — each rule that matches adds its weight; ≥ 30
  challenges, ≥ 60 blocks. Rules are plain regexes with labels in
  `src/injection.js` — read them, tune them, add your own.
- **Exploit scan** — payload rules for SQLi, XSS, traversal, command
  injection, JNDI, SSRF, XXE, NoSQL/LDAP, template injection,
  prototype pollution, CRLF, and GraphQL introspection, plus
  path-probe rules; ≥ 30 challenges, ≥ 60 blocks. See `src/exploits.js`.
- **Bot score** — user-agent signals (max 45) + missing-browser-header
  signals (max 35); ≥ 50 challenges, ≥ 85 blocks. Allowlisted agents
  score 0.
- **Rate limit** — 60 requests/minute sustained per IP by default,
  bursting to 60.

All thresholds are constructor options on `new Shield({...})`.

## Honest limits

824 Shield is **defense in depth, not a force field**:

- Pattern-based injection detection catches known attack shapes and
  casual evasion. A determined attacker with a novel phrasing can get
  past it — pair it with least-privilege design (your AI should never
  hold keys it doesn't need) and human review for high-impact actions.
- The default stores are in-memory: right for a single Node process and
  a starting point on Workers. For hard multi-isolate limits, back the
  Shield with KV / Durable Objects or Cloudflare's own rate-limit
  rules.
- Header heuristics identify *automation*, not *intent*. Some
  legitimate tools (and some crawlers you may want) look automated —
  that's what the challenge tier and the allowlist are for.
- This is v0.2.0: a working core, not a finished product.

## Layout

```
src/         injection.js · exploits.js · headers.js · botScore.js · rateLimiter.js · guard.js
adapters/    express.js · cloudflare.js
tests/       attack-simulation suite (node --test)
demo/        npm run demo
```

## License

Copyright © 2026 Nicholas Smith / 824.

824 Shield is free software under the **GNU General Public License
v3.0** — see the `LICENSE` file (the official GPL-3.0 text, from
gnu.org). You may use, study, modify, and redistribute it, including
commercially, provided derivative works stay under the GPL and carry
the same freedoms downstream.
