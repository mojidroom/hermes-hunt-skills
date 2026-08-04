# Wide Recon — Full Workflow (from user notebook + additions)

## 1. Domain Discovery (root domains)

**Objectives:** different root domains · increasing attack surface

- **Acquisitions of the main company:**
  - https://www.crunchbase.com
  - https://trackxn.com
- **Reverse whois on domain properties:**
  - https://website.informer.com
  - https://viewdns.info
  - [ADD] whoisxmlapi.com reverse whois (API), SecurityTrails reverse whois
- **Search through certificates:** `get_certificate walmart.com` (openssl func — see Certificate Search)
- **Read hunter's writeups**
- **Search engines dorks:**
  - `walmart has acquired`
  - `acquired by walmart`
  - `walmart acquisition list`
  - `"company All Rights Reserved." -inurl:walmart`
  - [ADD] `site:linkedin.com "works at <parent>"`, `"<parent> subsidiaries"`, Crunchbase + GitHub org search
- **Contact the security team**

## 2. Subdomain Discovery

**Objectives:** service discovery · origin IP of the server · new CIDRs

### Passive providers
```bash
# crt.sh
cat domains | while read d; do crtsh $d > ${d}.crtsh; done
# subfinder
for d in $(cat domains); do subfinder -d $d -all >> ${d}.subfinder; done
# abuseipdb
cat domains | while read d; do ./abuseipdb $d > ${d}.abuseipdb; done
```
- https://www.abuseipdb.com
- https://chaos.projectdiscovery.io
- https://subdomainfinder.c99.nl
- https://sourcegraph.com
- [ADD] certspotter API, rapiddns.io, SecurityTrails API, amass -passive, assetfinder

### Favicon + Shodan
```bash
python3 fav.py https://superbet.ro/static/img/icons/favicon.ico
# → shodan: http.favicon.hash:-657703595
# shodan also: http.title, ssl:"domain", "-" to exclude
```

### waybackurls (self note)
```bash
echo sempra.com | waybackurls | unfurl domains | dnsx -silent | tee sempra.subs | wc -l
# wildcard check: ping user.oncall.sempra.com (resolves) vs mamaduser.oncall.sempra.com (no resolve → no wildcard)
```

### Through web contents
```bash
# CSP urls
cat subdomains.txt | httpx -csp-probe -status-code -retries 2 -no-color | anew csp_probed.txt | cut -d ' ' -f1 | unfurl -u domains | anew -q csp_subdomains.txt
# DOM (JS analysis — see narrow-recon)
```

### Certificate search on CIDR
### PTR records on CIDR
```bash
dnsx -silent -resp-only -ptr
```

### DNS brute force
- **Static brute force** (ready wordlists):
```bash
curl -s https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt -o best-dns-wordlist.txt
curl -s https://wordlists-cdn.assetnote.io/data/manual/2m-subdomains.txt -o 2m-subdomains.txt
cat best-dns-wordlist.txt 2m-subdomains.txt | sort -u > subdomains-assetnote-merged.txt
crunch 1 4 abcdefghijklmnopqrstuvwxyz1234567890   # ~1.7M
cat 4.txt subdomains-assetnote-merged.txt | sort -u > static-final.txt
awk -v domain="sempra.com" '{print $0"."domain}' "static-final.txt" >> sempra.com.static
# resolve:
shuffledns -list sempra.com.static -d sempra.com -r ~/.resolvers -m $(which massdns) -mode resolve -t 30 -silent | tee sempra.com.static-shuffle
puredns bruteforce sempra.com.static sempra.com -t 30 -r ~/resolvers | tee sempra.com.static-puredns
# compare passive vs brute:
comm -13 firstfile secondfile >> output
```
- **Dynamic brute force** (permutation):
```bash
curl -s https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt -o altdns-words.txt && curl -s https://raw.githubusercontent.com/ProjectAnte/dnsgen/master/dnsgen/words.txt -o dnsgen-words.txt && cat altdns-words.txt dnsgen-words.txt | sort -u > words-merged.txt
# add years 2020-2025 into the wordlist too
cat sempra.com.subfinder | dnsgen -w words-merged.txt | wc -l   # 26M ok; >100M too much
# if subfinder results low → dynamic brute is feasible:
subfinder -d voorivex.academy -all | dnsgen words-merged.txt > voorivex.academy.dynamic
puredns resolve voorivex.academy.dynamic voorivex.academy -t 20 -l 50
# subs found NOT in subfinder output = interesting
```
- **Overall:** static + dynamic = dns_brute_results → compare with subdomain enumeration → hunt bugs

## 3. Content Delivery Network (CDN)

- Almost all sites behind CDN — drop CDN prefix in wide recon (useless)
- CDNs publish CIDR lists that change:
```bash
curl -s https://www.cloudflare.com/ips-v4 | mapcidr -silent -match-ip $(dig +short voorivex.academy)   # not behind CF if no match
# [ADD] ArvanCloud (Iran) IP list: https://www.arvancloud.ir/fa/ips.txt ; Akamai/AWS ranges too
```
- Every subdomain WITHOUT a CDN = interesting
- **cut-cdn tool:** `echo memoryleaks.ir | cut-cdn` → shows real IP if not behind CDN; keep updated with `cut-cdn -update-all`

## 4. Certificate Search (SSL)

**Objectives:** new domains · new subdomains · new properties
**Interesting fields:** Issuer (C/O/CN; big cos self-issue) · Subject (C/ST/L/O/CN — org, city) · X509v3 SubjectAlternativeName (DNS:)
**Search all IPs in the internet, parse SSL certs, extract useful data.**

```bash
get_certificate () { openssl s_client -showcert -servername $1 -connect $1:443 2> /dev/null | openssl x509 -inform pem -noout -text; }
get_certificate_nuclei () { input=""; while read line; do input="$input$line\n"; done < "${1:-/dev/stdin}"; echo $input | nuclei -t ~/ssl.yaml -silent -j | jq -r '.["extracted-results"][]'; }
echo time.ir | get_certificate_nuclei    # NO port in input
echo time.ir | nuclei -t ssl.yaml
```
- Sites: censys.io · shodan.io · crt.sh
```bash
curl -s "https://crt.sh/?q=target&output=json" | jq -r ".[].common_name" | sort -u
curl -s "https://crt.sh/?q=target&output=json" | jq -r ".[].name_value"  | sort -u
# censys dork: service.http.response.html_title: "superbet"
```

## 5. Name Resolution

- **dnsx** — simple bulk resolution
- **Resolvers:** 8.8.4.4 · 129.258.35.251 · 208.67.222.222
- **shuffledns:**
```bash
shuffledns -list subs.txt -d domain -r ~/.resolvers -m $(which massdns) -mode resolve -t 10 -silent | anew resolved | notify   # cron-able
```
- **puredns:** `puredns subs.txt -r ~/.resolver | tee resolved`
- **Recommendation: use the company's own nameserver** — better results than dnsx:
  - `dig NS` (no CDN) → company NS
  - CIDR port scan 53/UDP: `nmap CIDR -p 53 -n -Pn -sU`
  - Historical data from SecurityTrails
  - **Zone transfer:** `dig axfr @ns1.icollab.info icollab.info`
- Why target's NS? better resolution coverage

## 6. CIDR Discovery

**Objectives:** service discovery · certificate search (new domains/subs/properties) · skip CDN/VPS IPs (can't cert-search those) — confirm ownership via whois first.

- **ASN discovery:**
```bash
# bgpview API (automation)
curl -s https://api.bgpview.io/ip/175.178.201.26 | jq -r ".data.prefixes[].asn"
# bgp.he.net  ·  bgpview.docs.apiary.io
# [ADD] whois -h whois.cymru.com <ip> (Team Cymru); ipinfo.io/<ip>/json ASN+org; asnmap
```
- subdomain → IPs → ASNs:
```bash
subfinder -d domain -all | dnsx -silent -resp-only | sort -u | cut-cdn | get_ip_asn | sort -u | get_asn_details
# more accurate — cut-cdn misses some CDN subs
get_asn_details_ip / get_ip_prefix scripts (toolkit)
```
- Reverse lookup on IP properties

## 7. Service Discovery

**Objectives:** vulnerability discovery · wide recon resource discovery
- **Port scanning:** naabu top ports for large targets / all ports for small ranges:
  - `naabu -p 80,8000,8080,8880,2052,2082,2086,2095,443,2053,2083,2087,2096,8443,10443 -silent`
  - nmap more accurate: `-sV, -sT, -Pn, -n`
- **HTTP service detection:** httpx (best); make payloads legitimate
- **Virtual host discovery:** brute-force Host header (ffuf -H "Host: FUZZ.target")

## 8. Useful Flows

```
subdomain enumeration -> cut-CDN -> pure IPs
subdomain enumeration -> dnsx -> cut-CDN -> IP -> CIDR -> service discovery
domains -> historical websites (securitytrails) -> origin IP discovery
CIDR -> port scan -> certificate search -> domain + subdomains
CIDR -> httpx (443) -> certificate search -> domain + subdomains
CIDR -> port scan -> service discovery -> vulnerability discovery
CIDR -> PTR record enumeration -> subdomains (script in notes)
subdomain enum -> dnsx -> cut-CDN -> httpx(443) -> cert search -> domain + subdomains
```

## 9. Ephemeral Vulnerabilities & Continuous Wide Recon

- subfinder + abuse + crtsh → NR (new results) → compare → notify (cron)
- Subdomain takeover (CNAME / IP of dead subs)
- Fresh asset monitoring: [ADD] `js-change-monitor` / cron `notify`; re-run passive weekly; track new certs (certwatch, gungnir)
