# solve_blue.md — M2 · dev-registry
## Blue Team Detection & Response
**Vulnerability:** Unauthenticated Docker Registry v2 API + Credentials in Image ENV

---
## Detection

### Registry Access Log
```bash
grep --color=never -E 'v2/_catalog|manifests|blobs' /var/log/pul-registry/registry.log | \
    grep -v '127.0.0.1'
```
The log stores the actual client IP, not the literal placeholder `from=<external>`. The filter above excludes loopback requests and shows remote catalogue, manifest, and blob requests.

<img width="2035" height="597" alt="image" src="https://github.com/user-attachments/assets/09b330d9-e64d-4efc-aaa6-56e6e09a58ce" />



### Snort/Suricata Rule
```
alert http any any -> 11.x.x.x 5000 (
  msg:"GRIDFALL:Docker registry unauthenticated catalog enum";
  content:"GET"; http_method; content:"/v2/_catalog"; http_uri;
  content:!"Authorization"; http_header;
  sid:3000201; rev:1;
)
```

---
## Containment
```bash
# Add htpasswd auth to registry
apt-get install -y apache2-utils
htpasswd -Bc /opt/pul-registry/htpasswd pul-registry-svc
# Update registry config to require auth
```

## Eradication
1. **Rotate MinIO credentials** — MINIO_ACCESS_KEY/SECRET_KEY compromised
2. **Rebuild image** — Never bake credentials into image ENV; use Vault runtime injection
3. **Enable registry auth** — htpasswd or token-based auth required
4. **Audit all images** — Scan all registry images for embedded credentials

## IOC Summary
| Type | Value |
|---|---|
| Exposed Credential | MINIO_ACCESS_KEY=pul-build-svc / MINIO_SECRET_KEY=Artf@ct5tr!PUL24 |
| Root Cause | Credentials baked into Docker image ENV layer (failed Vault migration) |
| Next at Risk | M3 dev-artifacts (11.x.x.x:9000) |
