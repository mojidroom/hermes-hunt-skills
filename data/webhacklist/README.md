# WebHackList — Raw Research Archive

Complete raw extraction of the [Web Hacking Techniques Index](https://webhacklist.com)
research archive by **Soroush Dalili (@irsdl)**, preserved for offline reference and
hunting-signal mining.

> Source repo: https://github.com/irsdl/webhacklist (MIT) — every year's full
> **Top 10 Web Hacking Techniques** nominee list (not just winners) from 2006 → 2025,
> plus later audit finds the nomination rounds missed, plus the AI-collected 2026 leads.

## Layout

- `by-year/` — the raw per-year Markdown lists (`2006.md` … `2026-ai.md`), verbatim.
- `catalog/webhacklist-all.json` — all techniques as structured JSON.
- `catalog/webhacklist-catalog.csv` — flat table: `year, section, rank, title, url`.
- `source-README.md` — upstream README describing provenance and the PDF archive.

## Scale

- **1,545** technique records extracted (2026 prelim included).
- Sections per year: `Top 10`, `Other nominations`, `Missed from the original list`;
  2026-AI is categorized by theme (HTTP & protocol, Client-side & browser, Frameworks/
  injection/server-side, Authentication, AI agents/agentic browsers/MCP, CI-CD/supply-chain).

## How to use for hunting

Mine this for **techniques your hunt-* skills may not cover yet**. Novel / high-signal
classes seen in 2024–2026: CSPT gadget chains (CDN image proxies), CSS/ligature
exfiltration & "CSS bomb", HTTP desync variants (CRLF-powered, funky chunks, Ghost
ACL, CL.0), OAuth code-injection, passkey attacks, Python class pollution, ZIP parser
semantic gaps, parser differentials, XML/XXE resurrection, and a big new wave of
**AI-agent / MCP / agentic-browser** attack surface.

## Regeneration

Re-extract with:

```python
# parse all by-year/*.md lines matching:  - [Title](http...) 
import re, glob, json
recs=[]
for f in sorted(glob.glob('by-year/*.md')):
    year=f.split('/')[-1].replace('.md','')
    sec=None
    for line in open(f,encoding='utf-8'):
        if line.startswith('#'): sec=line.lstrip('#').strip(); continue
        m=re.match(r'^\s*[-*]\s+\[([^\]]+)\]\((https?://[^)]+)\)', line)
        if m: recs.append({'year':year,'section':sec,'title':m.group(1),'url':m.group(2)})
json.dump(recs, open('catalog/webhacklist-all.json','w'), indent=1)
```
