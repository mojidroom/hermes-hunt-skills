---
name: wide-recon
description: Asset discovery. Subdomains, certs, DNS, ASN, CDN bypass.
version: 1.0.0
author: mojtaba
license: MIT
metadata:
  hermes:
    tags: [recon, wide, subdomains, assets, discovery]
    related_skills: [recon-methodology, narrow-recon]
---

# Wide Recon — Asset Discovery

## Subdomain Enumeration
- crt.sh: `curl -sk "https://crt.sh/?q=%25.target.com&output=json"`
- subfinder: `subfinder -d target.com -all`
- amass: `amass enum -d target.com`
- assetfinder: `assetfinder --subs-only target.com`
- **waybackurls flow:** `echo target.com | waybackurls | unfurl domains | dnsx -silent`
- **CSP probe:** `cat subs.txt | httpx -csp-probe -status-code -retries 2 -no-color | anew csp_probed.txt | cut -d ' ' -f1 | unfurl -u domains | anew csp_subdomains.txt`
- **Favicon→Shodan:** `python3 fav.py <favicon-url>` → `http.favicon.hash:<hash>` on shodan
- **Dynamic brute (dnsgen):** `cat subs.txt | dnsgen -w words-merged.txt > domain.dynamic` → `puredns resolve domain.dynamic domain -t 20 -l 50`
- Static brute: assetnote `best-dns-wordlist.txt` + `2m-subdomains.txt` merged, `puredns bruteforce`
- **Compare passive vs brute:** `comm -13 file1 file2` — subs only in brute = interesting

## Certificate Search
- crt.sh: `curl -sk "https://crt.sh/?q=%25.target.com&output=json"`
- certspotter
- **Shodan CT API** 🔥
  - Certificates: `curl -sk "https://ctl.shodan.io/api/v1/domain/target.com"`
  - Hostnames (subdomains): `curl -sk "https://ctl.shodan.io/api/v1/domain/target.com/hostnames"`
  - سریع‌تر و تمیزتر از crt.sh — مستقیم لیست هاست‌نیم‌ها رو برمی‌گردونه
- Look for staging, dev, api subdomains
- **SAN mining:** openssl `get_certificate` func + nuclei `ssl.yaml` → SAN/CN/Issuer/Subject of every host (see references/wide-recon-full-workflow.md §4)

## CDN Detection / Bypass
- **cut-cdn:** `echo target | cut-cdn` (update: `cut-cdn -update-all`)
- Cloudflare check: `curl -s https://www.cloudflare.com/ips-v4 | mapcidr -silent -match-ip $(dig +short target)`
- ArvanCloud (Iran): `curl -s https://www.arvancloud.ir/fa/ips.txt | mapcidr -match-ip <ip>`
- Every subdomain WITHOUT CDN = interesting (origin candidate)

## Name Resolution (company NS — better than public resolvers)
- resolvers: 8.8.4.4, 129.258.35.251, 208.67.222.222
- `shuffledns -list subs -d domain -r ~/.resolvers -m $(which massdns) -mode resolve -silent | anew resolved | notify`
- `puredns resolve subs domain -r ~/.resolvers`
- Find company NS: `dig NS target` (no CDN) → nmap CIDR `-p 53 -n -Pn -sU`
- **Zone transfer:** `dig axfr @ns1.target target`

## DNS Bruteforce — LLM-Generated Wordlist (High Yield) 🔥
Passive sources (crt.sh/subfinder) miss most subdomains. DNS bruteforce with a **smart context-aware wordlist** finds what passive can't. Real case (vortexau): Claude generated 7M subdomains → resolved overnight → **200K new subdomains** (~2.8% resolve — high; typical is 0.5-2%).

```bash
# 1. LLM generates smart host list (context-aware: naming convention, company, tech)
#    → prompt LLM for candidate subdomain names (dev, api, staging, internal-ish, etc.)
#    → output to hosts.txt (millions of candidates)

# 2. Resolve with massdns (fast, resolvers.txt = trusted public+private resolvers)
massdns -r /path/resolvers.txt -t A -o S -w resolved.txt hosts.txt
# or puredns
puredns bruteforce hosts.txt target.com -r resolvers.txt -w resolved.txt

# 3. Extract only resolved names
grep -E " CNAME | A " resolved.txt | cut -d' ' -f1 | sort -u > found_subs.txt

# 4. Filter to live + distinct + in-scope
httpx -l found_subs.txt -silent -title -status-code -tech-detect
```

**Pitfalls:**
- **resolve ≠ bug** — many are dead/parked/CDN load-balancers; filter live + distinct + in-scope before testing
- Mass resolution can trip target monitoring + resolver rate limits — use `--rate` tuning and trusted resolvers
- Verify numbers against scope; huge "found X" numbers in tweets are often hyped / unverifiable
- LLM wordlist > generic wordlists (context-aware = higher precision/recall for that target)

## ASN Discovery
- whois, BGPView, bgp.he.net
- **bgpview API (automation):** `curl -s https://api.bgpview.io/ip/<ip> | jq -r ".data.prefixes[].asn"`
- **Team Cymru:** `whois -h whois.cymru.com <ip>`
- **Full flow (accurate):** `subfinder -d domain -all | dnsx -silent -resp-only | sort -u | cut-cdn | get_ip_asn | sort -u | get_asn_details`
- Reverse IP lookup
- **RIR workflow (ARIN/RIPE/APNIC...):** see `asn-infrastructure-mapping/references/rir-infrastructure-workflow.md`

## Origin IP Discovery (CDN Bypass)
1. DNS history (SecurityTrails, DNSDumpster)
2. SSL cert analysis
3. Subdomain with weak DNS (mail., ftp., dev.)
4. Email delivery headers
5. CloudFlare IP ranges + mass scan
6. Shodan/Censys
- **SNI pitfall:** many servers route by TLS SNI, not Host → use `curl --resolve target:443:ORIGIN_IP` or /etc/hosts (see origin-ip-discovery skill)

## Cross-Subdomain Auth Sharing
- Test main cookie on ALL subdomains
- Try .com and .ir variants
- Check conversation/chat microservices

## Full Workflow Reference
Complete wide-recon notebook (domain discovery, subdomain discovery, CDN, cert search, name resolution, CIDR, service discovery, useful flows, continuous recon):
`references/wide-recon-full-workflow.md`

## Verdict Quick-Check
**Trigger:** load at target kickoff for asset discovery — subdomains, certs, DNS, ASN, CDN bypass.
- Discovered subdomains/ASN/origin IPs = **leads** → verify live → route: stale CNAME → `hunt-subdomain` (takeover), origin IP → `origin-ip-discovery` (WAF bypass)
- `.com`/`.ir` variants and chat microservices often host forgotten APIs → fuzz after discovery
- Wildcard certs/DNS → expand scope carefully (only in-scope assets)
