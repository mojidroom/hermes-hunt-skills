# Disclosure Index Knowledge Base (bug-bounty-disclosures + Google Bug Hunters)

Curated from 11,304 public vulnerability disclosures (HackerOne 9,991, Bugcrowd 804, Code4rena 410, Immunefi 92, Intigriti 6, YesWeHack 1). Generated from the open archive at https://bug-bounty-disclosures.vercel.app/#api

## Scope
- Records: 11,304 | Researchers: 4.8K | With bounty: 2,194 | Platforms: 6
- Updated: 16 Aug 2026


## Class Distribution

- Other: 3473
- Cross-site scripting: 1737
- Access control: 1359
- Authentication: 1149
- Information disclosure: 1119
- Smart contracts: 419
- Command execution: 395
- Injection: 365
- CSRF: 309
- Business logic: 300
- SSRF: 207
- File security: 173
- SQL injection: 171
- Request smuggling: 54
- Subdomain takeover: 52
- XXE: 22

## Top 25 Bounties Overall

- $50,000 | Information disclosure | Critical | HackerOne | 2021-07-26 | Github access token exposure — https://hackerone.com/reports/1087489
- $40,000 | Other | Unrated | HackerOne | 2021-23-12 | Cache Poisoning at Scale — https://youst.in/posts/cache-poisoning-at-scale/
- $35,000 | Access control | Critical | HackerOne | 2025-02-26 | Account Takeover via Password Reset without user interactions — https://hackerone.com/reports/2293343
- $33,510 | Command execution | Critical | HackerOne | 2022-09-13 | RCE via the DecompressedArchiveSizeValidator and Project BulkImports (behind feature flag) — https://hackerone.com/reports/1609965
- $33,510 | Command execution | Critical | HackerOne | 2022-10-06 | Remote Command Execution via Github import — https://hackerone.com/reports/1679624
- $29,000 | File security | Critical | HackerOne | 2022-03-21 | Arbitrary file read via the bulk imports UploadsPipeline — https://hackerone.com/reports/1439593
- $25,000 | SQL injection | Critical | HackerOne | 2018-07-27 | SQL Injection in report_xml.php through countryFilter[] parameter — https://hackerone.com/reports/383127
- $25,000 | Command execution | Critical | HackerOne | 2021-07-29 | Exposed Kubernetes API - RCE/Exposed Creds — https://hackerone.com/reports/455645
- $25,000 | Other | Critical | HackerOne | 2025-01-21 | Disclosing PolicyPageAssetGroup in Private Programs via /graphql `gid://hackerone/PolicyPageAssetGroupsIndex::PolicyPageAssetGroup/{id}` — https://hackerone.com/reports/1618347
- $25,000 | Information disclosure | Critical | HackerOne | 2025-04-01 | The /reports/:id.json endpoint discloses potentially sensitive user attributes when reporter summary is present — https://hackerone.com/reports/3000510
- $22,300 | Access control | Medium | HackerOne | 2022-11-04 | RepositoryPipeline allows importing of local git repos — https://hackerone.com/reports/1685822
- $22,300 | Other | Unrated | HackerOne | 2019-24-10 | Responsible denial of service with web cache poisoning — https://portswigger.net/research/responsible-denial-of-service-with-web-cache-poisoning
- $20,160 | Command execution | Critical | HackerOne | 2019-08-10 | Potential pre-auth RCE on Twitter VPN — https://hackerone.com/reports/591295
- $20,000 | Access control | Critical | HackerOne | 2018-10-31 | Getting all the CD keys of any game — https://hackerone.com/reports/391217
- $20,000 | Access control | Critical | HackerOne | 2022-06-07 | Steal private objects of other projects via project import — https://hackerone.com/reports/743953
- $20,000 | Authentication | High | HackerOne | 2019-12-03 | Account takeover via leaked session cookie — https://hackerone.com/reports/745324
- $20,000 | Access control | Critical | HackerOne | 2022-06-07 | Private objects exposed through project import — https://hackerone.com/reports/767770
- $20,000 | File security | Critical | HackerOne | 2020-04-27 | Arbitrary file read via the UploadsRewriter when moving and issue — https://hackerone.com/reports/827052
- $20,000 | Command execution | Critical | HackerOne | 2021-04-20 | RCE via unsafe inline Kramdown options when rendering certain Wiki pages — https://hackerone.com/reports/1125425
- $20,000 | Command execution | Critical | HackerOne | 2021-05-14 | RCE when removing metadata with ExifTool — https://hackerone.com/reports/1154542
- $18,000 | Command execution | Critical | HackerOne | 2016-12-17 | Struct type confusion RCE — https://hackerone.com/reports/181879
- $16,000 | File security | Critical | HackerOne | 2021-05-24 | Arbitrary file read during project import — https://hackerone.com/reports/1132378
- $16,000 | Cross-site scripting | Critical | HackerOne | 2021-10-18 | Stored XSS in markdown via the DesignReferenceFilter — https://hackerone.com/reports/1212067
- $15,300 | Authentication | High | HackerOne | 2020-01-08 | Token leak in security challenge flow allows retrieving victim's PayPal email and plain text password — https://hackerone.com/reports/739737
- $15,250 | Business logic | Critical | HackerOne | 2018-02-07 | Ability to bypass partner email confirmation to take over any store given an employee email — https://hackerone.com/reports/300305

## Notable Recent (2024-2026) High-Value

- $35,000 | Access control | Critical | HackerOne | 2025-02-26 | Account Takeover via Password Reset without user interactions — https://hackerone.com/reports/2293343
- $25,000 | Other | Critical | HackerOne | 2025-01-21 | Disclosing PolicyPageAssetGroup in Private Programs via /graphql `gid://hackerone/PolicyPageAssetGroupsIndex::PolicyPageAssetGroup/{id}` — https://hackerone.com/reports/1618347
- $25,000 | Information disclosure | Critical | HackerOne | 2025-04-01 | The /reports/:id.json endpoint discloses potentially sensitive user attributes when reporter summary is present — https://hackerone.com/reports/3000510
- $15,000 | Other | High | HackerOne | 2025-04-23 | Groups module can halt chain when handling a proposal with malicious group weights — https://hackerone.com/reports/3018307
- $12,500 | Other | High | HackerOne | 2025-08-15 | Internal Access to Hackerone confluence Docs — https://hackerone.com/reports/3113398
- $12,500 | Other | Unrated | HackerOne | 2026-04-16 | DOS via Mutation Aliasing in GraphQL Account Recovery Phone Number Verification API — https://hackerone.com/reports/3287208
- $12,000 | Authentication | Critical | HackerOne | 2024-07-13 | Account Takeover via Authentication Bypass in TikTok Account Recovery — https://hackerone.com/reports/2443228
- $12,000 | Command execution | Critical | HackerOne | 2026-08-05 | Unauthenticated RCE in Taskcluster web-server via GraphQL filter argument (sift $where) — https://hackerone.com/reports/3782701
- $10,000 | Other | High | HackerOne | 2025-04-18 | sys_fsc2h_ctrl kernel stack free — https://hackerone.com/reports/2900606
- $10,000 | Other | High | HackerOne | 2026-05-01 | Double fdrop on a socket through sys_netcontrol — https://hackerone.com/reports/3320669
- $8,000 | Other | Critical | HackerOne | 2025-01-18 | CVE-2022-40604: Apache Airflow: Format String Vulnerability — https://hackerone.com/reports/1707287
- $8,000 | Command execution | Critical | HackerOne | 2024-01-20 | Remote code execution and exfiltration of secret tokens by poisoning the mozilla/fxa CI build cache — https://hackerone.com/reports/2255750
- $7,500 | Access control | High | HackerOne | 2025-02-24 | Exposed proxy allows to access internal reddit domains — https://hackerone.com/reports/2967634
- $7,000 | Injection | High | HackerOne | 2026-06-17 | Authenticated Elasticsearch Painless script execution via Query.search.sort_query on hackerone.com/graphql — https://hackerone.com/reports/3694007
- $6,000 | Command execution | High | HackerOne | 2025-07-29 | Mozilla VPN Clients: RCE via file write and path traversal — https://hackerone.com/reports/2995025
- $5,580 | Authentication | High | HackerOne | 2025-07-23 | Mint Oauth2 access token for targeted user — https://hackerone.com/reports/1148364
- $5,420 | Other | High | HackerOne | 2024-09-25 | Possible DoS Vulnerability with Range Header in Rack — https://hackerone.com/reports/2520679
- $5,000 | Other | High | HackerOne | 2025-06-13 | DOS of RSKJ server — https://hackerone.com/reports/2105808
- $5,000 | Access control | Medium | HackerOne | 2024-02-08 | IDOR on GraphQL queries BillingDocumentDownload and BillDetails — https://hackerone.com/reports/2207248
- $5,000 | Cross-site scripting | High | HackerOne | 2024-04-05 | Reflected XSS on Pangle Endpoint — https://hackerone.com/reports/2352968
- $5,000 | File security | High | HackerOne | 2026-06-14 | Burp Suite Professional: browser-powered crawl can write attacker-controlled files through file input handling — https://hackerone.com/reports/3712279