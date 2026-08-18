# 🤖 Hermes Hunt — Agent Framework

A **hunting swarm** structured around the `hunt-*` skill family. Each skill has a
**dedicated agent** that hunts one bug class; a `verify-skeptic` agent
adversarially validates every finding before anything is reported; a `dispatch`
orchestrator fingerprints the target and routes the right hunters.

## Directory layout

```
hermes-hunt-skills/
├── skills/                     # the actual hunt-* skill library (ground truth)
│   ├── hunt-xss/SKILL.md
│   ├── hunt-ssrf/SKILL.md
│   ├── hunt-sqli/SKILL.md
│   └── ... (65 skill dirs)
├── agents/                     # the agent layer  <-- THIS framework
│   ├── dispatch.md             # orchestrator: fingerprint + load budget + spawn
│   ├── recon-wide.md           # asset discovery agent
│   ├── recon-narrow.md         # deep recon agent (JS, params, API)
│   ├── <vuln>-hunter.md        # ONE dedicated hunter per hunt-* skill (62)
│   └── verify-skeptic.md       # independent finding verifier (red-team skeptic)
└── data/                       # research archive (webhacklist catalog, disclosure-index KB)
```

## 📚 Global knowledge base (cross-class references)

Every `hunt-*` skill ships a `references/` corpus. Two new curated corpora were
added from the open disclosure archives and should be consulted by the matching
hunter and by `verify-skeptic`:

- `references/disclosure-index-{class}.md` — top 30 real reports per bug class
  (title, researcher, severity, bounty, date, source URL) extracted from the
  11,304-record archive (`bug-bounty-disclosures.vercel.app`, HackerOne /
  Bugcrowd / Code4rena / Immunefi / Intigriti / YesWeHack). Ground-truth
  examples for each class.
- `references/google-bug-hunters-recent.md` — recent (2025–2026) Google VRP
  disclosures: AI/LLM-agent surfaces, cross-tenant cloud issues, Zip-Slip→RCE,
  TLS handshake desync, cache poisoning via space forwarding, unbounded-body
  DoS. Rich source of *current* attacker priorities.
- `security/hunting-techniques-db/references/disclosure-index-knowledge-base.md`
  — aggregate KB: class distribution, top bounties, notable 2024–2026 findings.

Hunters should pull the class-specific reference first to seed real attack
shapes and payout context before writing bespoke payloads.

## How the swarm runs

```
operator scope & target
  -> recon-wide        (assets: subs, certs, ASN, CDN bypass)
  -> recon-narrow      (deep: JS bundles, params, API discovery, auth/api-style)
  -> dispatch           (fingerprint -> tier precedence -> 8-skill load cap)
  -> specialized hunters (one class each, slim context, validated auth only)
  -> verify-skeptic     (reproduces + basis-of-truth + public-vs-private gate)
  -> report-writing
```

## Agent inventory

**Orchestration & recon**
- `agents/dispatch.md` — mode/fingerprint/surface routing, auth preflight, load budget
- `agents/recon-wide.md` — subdomains, certs, DNS, ASN, CDN bypass
- `agents/recon-narrow.md` — JS analysis, params, API endpoint discovery

**Hunters (one per `hunt-*` skill, 62 total)** — e.g.
`xss-hunter`, `sqli-hunter`, `ssrf-hunter`, `idor-hunter`, `rce-hunter`,
`graphql-hunter`, `xxe-hunter`, `ssti-hunter`, `auth-bypass-hunter`,
`business-logic-hunter`, `http-smuggling-hunter`, `cors-hunter`, `csrf-hunter`,
`open-redirect-hunter`, `race-condition-hunter`, `file-upload-hunter`, ... (full list in `agents/`)

**Verifier**
- `agents/verify-skeptic.md` — adversarial reviewer. Reproduces every finding,
  applies the class's ground-truth gate (e.g. OOB-or-it-didn't-happen for SSRF),
  applies the public-vs-private rule (#1 N/A trap), re-calibrates severity.
  Verboses: `CONFIRMED | LIKELY | INSUFFICIENT-EVIDENCE | REFUTED | N/A`.

## Key principles

- **One agent per bug class** — each hunter loads exactly one skill, keeping
  context slim and focus sharp.
- **Skeptic-last gate** — hunters self-triage to `confirmed`/`probable` with raw
  evidence, but only `verify-skeptic`'s verdict lets a finding be reported.
- **Public ≠ bug** — the verifier separates public website data from private user
  data before any IDOR / info-leak claim is accepted.
- **Auth-aware routing** — `dispatch` fingerprints token vs cookie vs key and
  turns CSRF/CORS/session hunters off on pure-token targets.

## Usage

Point `dispatch` at an authorized target + scope. Provide auth context if the
target is grey-box. Everything else is routed automatically.