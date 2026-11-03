# solve_blue.md — M3 · dev-artifacts
## Blue Team Detection & Response
**Vulnerability:** Public S3 Bucket ACL on pul-code-reports

---
## Detection
```bash
# Check artifact store log for unauthenticated bucket access
grep "UNAUTH_BUCKET_ACCESS\|pul-code-reports" /var/log/pul-artifacts/artifacts.log
```
Signature: GET requests to `pul-code-reports` without Authorization header from non-internal IP.

### Snort Rule
```
alert http any any -> 11.x.x.x 9000 (
  msg:"GRIDFALL:Public S3 bucket access without auth";
  content:"GET"; http_method; content:"pul-code-reports"; http_uri;
  content:!"Authorization"; http_header;
  sid:3000301; rev:1;
)
```

## Containment
1. Set `pul-code-reports` bucket to private immediately
2. Revoke `sqa_pul_admin_2024_gridfall` SonarQube token
3. Block source IP from reaching port 9000

## Eradication
1. Audit ALL bucket ACLs — remove public access from all buckets
2. Rotate SonarQube admin token immediately
3. Remove `sonarqube-access.env` from artifact storage — secrets must NEVER be stored as S3 objects
4. Implement bucket policy enforcement — no bucket may be set public without CISO approval

## IOC Summary
| Type | Value |
|---|---|
| Exposed Credential | SONAR_TOKEN=sqa_pul_admin_2024_gridfall |
| Root Cause | Misconfigured public-read ACL on pul-code-reports bucket |
| Next at Risk | M4 dev-sonar (11.x.x.x:9200) |
