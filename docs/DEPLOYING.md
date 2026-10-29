# Deploying 824 Shield — the platform matrix

One Shield, every major host. Find your platform, use its adapter.

| Platform | Adapter | Notes |
| --- | --- | --- |
| Cloudflare Workers | `824-shield/cloudflare` | In production on both 824 sites |
| Express (any Node host: VPS, Render, Railway, Fly.io, App Service, Elastic Beanstalk) | `824-shield/express` | `shieldMiddleware` + `headersMiddleware` |
| AWS Lambda (API Gateway / ALB) | `824-shield/aws-lambda` | Payload 1.0 + 2.0, base64 bodies |
| Azure Functions (Node v4) | `824-shield/azure-functions` | Web-standard model |
| Google Cloud Functions / Firebase Functions | `824-shield/google-cloud` | (req, res) signature |
| Vercel (Edge route handlers) | `824-shield/vercel` | Node (req,res) functions: use the google-cloud shape |
| Next.js (App Router route handlers) | `824-shield/next` | Also usable in middleware |
| Netlify Edge Functions | `824-shield/netlify` | Uses `context.ip` |
| Deno Deploy / Supabase Edge Functions | `824-shield/deno` | Uses conn info / x-forwarded-for |
| Bun (Bun.serve) | `824-shield/bun` | Uses `server.requestIP` |
| Fastly Compute | `824-shield/fastly` | Uses Fastly-Client-IP |
| Hono (Workers / Bun / Deno / Node) | `824-shield/hono` | One middleware, four runtimes |
| Fastify | `824-shield/fastify` | preValidation + onSend hooks |
| Koa | `824-shield/koa` | Mount after the body parser |
| **Anything else — PHP, WordPress, Java, .NET, legacy** | **`apps/shield-proxy.js`** | Zero-dependency reverse proxy; no code changes to the app it guards |

## Rules of thumb

- Put the platform's WAF (AWS WAF, Azure Front Door WAF, Cloud
  Armor, Cloudflare WAF) **in front** for network-layer attacks;
  Shield handles the application semantics behind it.
- Create **one Shield instance per process/bundle** so its
  in-memory rate and login guards persist across warm requests.
- Stream decisions to your SIEM with `siemAudit` (CEF / syslog /
  NDJSON) — see `src/siem.js`.
- Account-level hardening for AWS and Azure lives in
  [CLOUD-HARDENING.md](CLOUD-HARDENING.md); the critical-
  infrastructure mission lives in
  [PROTECTING-NATIONS.md](PROTECTING-NATIONS.md).
