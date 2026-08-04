---
name: hunt-metrics-exposure
description: "Hunt public /metrics, /health, and actuator endpoints leaking AI usage, DB pools, and operational intelligence."
version: 1.1.0
revision_date: 2026-07-25
license: MIT
category: redteam
tags: [metrics, exposure, hunt, redteam]
---

## When to Use

The target uses modern observability tooling (Go, .NET, Java, Node.js). These frameworks often expose `/metrics`, `/health`, and `/status` endpoints that are forgotten behind auth. Unlike application data leaks, metrics leaks reveal the ENTIRE operational profile: which AI models are used, how many users are active, database connection exhaustion, and third-party service dependencies.

---

## Phase 1 — Discover Metrics Endpoints

```bash
TARGET="https://target.com"

# Common observability paths
for ep in metrics health status ready live readyz healthz \
  actuator/health actuator/metrics actuator/prometheus \
  Telescope telescope horizon debug; do
  code=$(curl --max-time 30 --connect-timeout 10 -sk -o /tmp/metrics_${ep}.txt -w "%{http_code}" \
    "${TARGET}/${ep}" 2>/dev/null)
  if [ "$code" = "200" ]; then
    size=$(wc -c < /tmp/metrics_${ep}.txt)
    echo "  /${ep}: HTTP 200 (${size} bytes)"
  fi
done
```

---

## Phase 2 — Analyze Prometheus Metrics

```bash
# Count unique metric families (each reveals a subsystem)
grep -c '^# HELP' /tmp/metrics_metrics.txt

# Extract AI/ML model usage
grep -i 'ai_\|model\|llm\|openai\|gemini\|copilot' /tmp/metrics_metrics.txt

# Extract database pool states
grep -i 'db_pool\|database\|connection' /tmp/metrics_metrics.txt

# Extract third-party dependencies
grep -i 'stripe\|openai\|sendgrid\|twilio\|email' /tmp/metrics_metrics.txt

# Extract request volumes (user activity)
grep -i 'http_request\|api_request\|grpc_request' /tmp/metrics_metrics.txt

# Extract circuit breaker states (service health)
grep -i 'circuit_breaker' /tmp/metrics_metrics.txt
```

---

## Phase 3 — Analyze Health/Status Endpoints

```bash
# Spring Boot Actuator
curl --max-time 30 --connect-timeout 10 -sk "${TARGET}/actuator/health" | python3 -m json.tool
curl --max-time 30 --connect-timeout 10 -sk "${TARGET}/actuator/metrics" | python3 -m json.tool
curl --max-time 30 --connect-timeout 10 -sk "${TARGET}/actuator/env" | python3 -m json.tool  # May leak env vars

# Custom health endpoints
curl --max-time 30 --connect-timeout 10 -sk "${TARGET}/health" | python3 -m json.tool
curl --max-time 30 --connect-timeout 10 -sk "${TARGET}/api/health" | python3 -m json.tool

# Laravel Telescope (if exposed)
curl --max-time 30 --connect-timeout 10 -sk "${TARGET}/telescope/requests" | head -c 500
```

---

## What Metrics Reveal

| Metric | Intelligence Gained |
|--------|-------------------|
| `ai_analyzer_output_total{model="gpt-5-mini"}` | Which AI models are used, usage volume |
| `db_pool_idle_connections{pool="api"}` | Database pool sizing, connection exhaustion risk |
| `circuit_breaker_state{client="stripe"}` | Third-party dependencies and their health |
| `clinical_copilot_sse_active` | Real-time user count for specific features |
| `http_requests_total` | Request volume, peak hours, user activity |
| `app_version` / `build_info` | Deployed version, build timestamps |

---

## Verification

- **Confirmed exposure**: `/metrics` returns Prometheus text format (lines starting with `# HELP` or `# TYPE`)
- **Actuator exposure**: `/actuator/health` returns JSON with component statuses
- **False positive**: Endpoint returns `{"status":"ok"}` only (minimal health check, not a metrics leak)
- **Severity upgrade**: If `/actuator/env` or `/actuator/configprops` is exposed → CRITICAL (environment variables leaked)

---

## MDPsec Verified Patterns (2 real metrics-exposure reports)

Real-world primitives from mdpsec.com reports:

1. **High-cardinality label anti-pattern leaks wallet master keys** — `/metrics` (Prometheus) reachable unauthenticated; instrumentation records RAW HTTP request path as a metric label; wallet API paths contain extended public keys → `grep -oE '(xpub|ypub|zpub)[A-Za-z0-9]+'` → ~3,200 unique xpubs in one response (84). Detection: grep telemetry for key-pattern regexes (xpubs, wallet addresses, txids); check route labels vs normalized paths.
2. **IP allowlist bypass via path normalization** — edge-gateway allowlist checks RAW path, normalization happens AFTER check passes: `/./metrics` bypasses fleet A (strips leading dot-segment), `/metrics/` bypasses fleet B (collapses trailing slash), combined `/./metrics/` + `curl --path-as-is` defeats both (63). Path-generic: `/./api/admin` → 401 (reaches app) vs direct 403 — proves allowlist fully circumventable.
3. **Per-replica in-memory counters** — each request hits different replica → different subset; poll repeatedly + union → several thousand distinct emails across 100+ orgs (login-count labels carried real person email + employer org + product).
4. **Feature-flag admin endpoints public** — internal debug/monitoring endpoints bound to public interface with no auth: 116 feature flags, token inventory with wildcard production client token, segment definitions leak 23 privileged user ID hashes + SSO user IDs; flag-evaluation with leaked enterprise userId flips SSO/testnet; token-validation endpoint = brute-force oracle (42).
5. **Mutable identity claim + IAM telemetry (67)** — IdP tokens carrying user-writable attributes as principal; identity codes exposed in ordinary roster/workspace responses; attribute-update accepting arbitrary values → peer editor (level 1) and region administrator (level 6) takeover from fresh self-signup (paired with hunt-information-disclosure #13).

Cross-ref `mdpsec-report-knowledge` for the full index.

## What Next

- AI model usage metrics → pivot to `hunt-llm-ai` (prompt injection on discovered models)
- DB pool metrics showing overload → DoS attack surface identified
- Circuit breaker states for Stripe/email → infrastructure dependency map for chained attacks
- Combine with `hunt-schema-enumeration` for full target profile

---

## Verification

Run this self-test to confirm metrics-exposure hunting readiness:

1. **Skill integrity** — confirm the skill file is readable and well-formed:
   ```bash
   grep -q "name: hunt-metrics-exposure" SKILL.md && echo "PASS: skill frontmatter present" || echo "FAIL"
   grep -q "revision_date:" SKILL.md && echo "PASS: revision date present" || echo "FAIL"
   ```

2. **Category check** — confirm the skill has a category:
   ```bash
   grep -q "category:" SKILL.md && echo "PASS: category present" || echo "FAIL"
   ```

3. **Pitfalls section** — confirm pitfalls are documented:
   ```bash
   grep -q "^## Pitfalls" SKILL.md && echo "PASS: pitfalls section present" || echo "FAIL"
   ```

All 3 tests verify the skill is properly structured and ready for use.

---

## Pitfalls
- **Prometheus /metrics without secrets** — metrics endpoints exposing request counts are informational. Need labels containing PII, internal hostnames, or credentials.
- **Spring Boot Actuator /actuator/metrics** — metrics are intentionally exposed for monitoring. Only report if they leak sensitive data (usernames in labels, internal IPs).
- **JMX without auth** — JMX exposure without authentication is critical only if write operations (MBean invocation) are possible. Read-only JMX is informational.
- **Health endpoint without sensitive data** — `/health`, `/status`, `/ready` endpoints are designed to be public. Need leaked internal data.
