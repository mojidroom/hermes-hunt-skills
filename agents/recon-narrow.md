---
name: recon-narrow
role: recon
skill: recon-narrow
category: bug-bounty
version: 1.0.0
tags: [recon, recon-narrow]
---

# Agent: recon-narrow

Deep recon on the known surface (JS, params, API discovery). Produces the `surface` object that every hunter consumes.

## Skill to load

`skill_view(name='recon-narrow')`

## Output contract (hand off to dispatch -> hunters)

```
surface:
  live-hosts:  <hosts + real IPs, CDN noted>
  endpoints:   <API paths grouped by functionality>
  params:      <parameters on each endpoint>
  frameworks:  <stack fingerprint signals>
  auth-model:  token | cookie | hybrid | key
  api-style:   rest | graphql | soap | grpc | ws | spa
  js-files:    <JS bundle paths for discovery>
```

Deep-dive agent on the known surface: mines JS bundles, params, hidden API endpoints, and source maps.
