# Securing AWS and Azure Accounts with 824 Shield

824 Shield protects the **workloads** running inside a cloud account —
the APIs, web apps, and functions attackers actually talk to. This
release adds adapters for **AWS Lambda** (API Gateway / ALB) and
**Azure Functions** (v4 model), joining the existing Express and
Cloudflare adapters.

Honest boundary, same as always: no application library can
reconfigure somebody's cloud account. Account-level security is
settings, and the checklist below is the part that has to be done in
the console/IaC. Shield + this checklist + the cloud's own WAF is
the full sandwich.

## Where Shield plugs in

| Cloud surface | Adapter | In front of it |
| --- | --- | --- |
| AWS Lambda + API Gateway / ALB | `824-shield/aws-lambda` | AWS WAF |
| Azure Functions (Node v4) | `824-shield/azure-functions` | Azure Front Door WAF |
| Containers / VMs / App Service (Express) | `824-shield/express` | Cloud WAF or Shield headers only |
| Static + API on Cloudflare | `824-shield/cloudflare` | Cloudflare WAF |

## AWS account checklist

1. **Root account**: MFA on, no access keys, used for nothing else.
2. **IAM**: least-privilege roles per workload; no `*:*` policies in
   production; IAM Access Analyzer findings at zero; humans sign in
   through Identity Center with MFA.
3. **Logging**: CloudTrail in every region (organization trail if
   you have one), GuardDuty on, Security Hub on; ship Shield's SIEM
   stream (`src/siem.js`) to the same destination as your app logs.
4. **Network**: security groups deny by default; no `0.0.0.0/0` SSH/RDP
   — use SSM Session Manager / Azure Bastion equivalents instead.
5. **Data**: S3 Block Public Access at the *account* level; buckets
   versioned + encrypted; snapshots never public.
6. **Secrets**: Secrets Manager / SSM Parameter Store, never env
   files in repos; automatic rotation where supported.
7. **Edge**: AWS WAF managed rules in front, Shield behind it for
   application semantics (injection, stuffing, probes) WAF regexes
   don't understand.

## Azure account checklist

1. **Identity**: MFA + Conditional Access for every human; break-
   glass accounts excluded from CA but alarmed; no shared admins.
2. **RBAC**: least privilege per resource group; deny assignments
   understood before used; Privileged Identity Management for
   just-in-time elevation on production subscriptions.
3. **Logging**: Activity Log exported to Log Analytics; Microsoft
   Defender for Cloud enabled on production subscriptions; Shield's
   SIEM stream forwarded to the same workspace (Sentinel if you
   run it).
4. **Network**: NSGs deny by default; no public RDP/SSH — use Azure
   Bastion; Private Endpoints for storage/databases where feasible.
5. **Data**: storage accounts with public blob access disabled,
   TLS 1.2+ enforced, soft delete on; Key Vault purge protection
   on.
6. **Secrets**: Key Vault references from apps/functions; never
   connection strings in source.
7. **Edge**: Azure Front Door WAF (managed rule sets) in front,
   Shield behind it at the function/app layer.

## Operating the Shield layer in cloud

- One Shield instance per function app / Lambda bundle (module
  scope), so its in-memory rate and login guards persist across
  warm invocations.
- Send decisions to the SIEM: `onDecision: siemAudit({...})` —
  CEF/syslog/NDJSON all parse natively in Sentinel, Splunk, and
  CloudWatch-adjacent pipelines.
- Treat `challenge` responses as telemetry gold: a rising challenge
  rate is your early-warning for a scanning campaign.

---

*824 Shield — Copyright © 2026 Nicholas Smith / 824. GPLv3.*
