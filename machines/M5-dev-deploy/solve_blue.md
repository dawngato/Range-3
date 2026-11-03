# solve_blue.md — M5 · dev-deploy
## Blue Team Detection & Response
**Vulnerability:** Dry-run API returning K8s manifest with ServiceAccount token

---
## Detection
```bash
grep "DRYRUN_MANIFEST_RETURNED" /var/log/pul-deploy/deploy.log
# Shows: app=pul-ota-firmware contains_sa_token=True from=<attacker_ip>
```

### Snort Rule
```
alert http any any -> 11.x.x.x 8888 (
  msg:"GRIDFALL:Deploy Commander dry-run manifest extraction";
  content:"POST"; http_method; content:"/sync"; http_uri;
  content:"dryRun=true"; http_uri;
  sid:3000501; rev:1;
)
```

## Containment
1. Revoke `dc-pul-deploy-2024-gridfall` token immediately
2. Rotate K8s ServiceAccount token `pul-ota-deployer-token`
3. Block attacker IP from reaching 193.x.x.x:6443

## Eradication
1. **Remove SA token from dry-run response** — dry-run should never return Secrets
2. **Rotate** ALL K8s ServiceAccount tokens that were included in any dry-run response
3. **Implement** Kubernetes RBAC — pul-ota-deployer SA should have minimal namespace-scoped permissions only
4. **Audit** all Deploy Commander API logs for dryRun=true calls

## IOC Summary
| Type | Value |
|---|---|
| API Called | POST /api/applications/pul-ota-firmware/sync?dryRun=true |
| Token Used | dc-pul-deploy-2024-gridfall (from M4) |
| Credential Exposed | K8s SA token for pul-ota-deployer |
| Cluster at Risk | 193.x.x.x:6443 (RNG-CLD-01) |
