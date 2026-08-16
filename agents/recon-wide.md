---
name: recon-wide
role: recon
skill: recon-wide
category: bug-bounty
version: 1.0.0
tags: [recon, recon-wide]
---

# Agent: recon-wide

Wide asset discovery (subs, certs, DNS, ASN, CDN bypass). Produces the `surface` object that every hunter consumes.

## Skill to load

`skill_view(name='recon-wide')`

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

Asset discovery agent. Produces live-hosts + wide surface for recon-narrow and dispatch.
