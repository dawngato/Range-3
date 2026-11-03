# solve_red.md — M1 · dev-jenkins
## Red Team Solution Writeup
**Range:** RNG-DEV-01 · VIKAS TANTRA
**Machine:** M1 — Jenkins CI/CD Server
**Vulnerability:** Anonymous Jenkins API access and unauthenticated build artifact access
**MITRE ATT&CK:** T1190 · T1552.001
**Severity:** Hard

---

## Objective

From Kali, identify Jenkins on the confirmed range host and verify anonymous API access. The current deployment has no archived artifact on the documented successful build, so the artifact credential step cannot be completed until the lab artifact is restored. Keep the same Kali terminal open for M1–M5 so the private workspace and later extracted values remain available.

## Environment

| Item | Value |
|---|---|
| Entry | Direct access from Kali |
| Target | `203.0.3.36` |
| Jenkins port | `8080` |
| Authentication | Anonymous API access |
| Expected job | `pul-firmware-build` |
| Expected artifact | `deploy-bundle/docker-config.json` |

## Step-by-Step

### Step 1 — Scan the confirmed host

```bash
nmap -Pn -sV -p 22,8080,5000,9000,9200,8888 203.0.3.36
```
<img width="1320" height="409" alt="WindowsTerminal_mRdhAsprXP" src="https://github.com/user-attachments/assets/92706a48-b2b0-4c39-9894-14c3feb1e751" />

This is earlier scan evidence. The original jump-host key and `11.x.x.x/24` subnet are placeholders and do not apply to this deployment.

### Step 2 — Confirm anonymous Jenkins access

```bash
curl --max-time 8 -fsS http://203.0.3.36:8080/api/json | jq '{useSecurity, jobs}'
```
<img width="1114" height="616" alt="WindowsTerminal_tOqmBSqZgX" src="https://github.com/user-attachments/assets/bff05b83-66cb-43de-995a-2e3b02ebbd1d" />

The unauthenticated request returns HTTP 200 and reports `useSecurity: false`.

### Step 3 — Enumerate build jobs

```bash
curl --globoff --max-time 8 -fsS "http://203.0.3.36:8080/api/json?tree=jobs[name,url,lastBuild[result,artifacts[*]]]" | jq .
```

`--globoff` is required because curl otherwise interprets square brackets in the `tree=` query as URL glob syntax. The live API lists `pul-firmware-build` and its last build as successful. The current build API reports an empty artifacts array.

### Step 4 — Check whether the artifact is present

Create the private workspace used by the later machine steps:

```bash
export RANGE3_DIR="$(mktemp -d /tmp/range3.XXXXXX)"
```

```bash
chmod 700 "$RANGE3_DIR"
```

Inspect the last successful build's artifact list:

```bash
curl --globoff --max-time 8 -fsS "http://203.0.3.36:8080/job/pul-firmware-build/lastSuccessfulBuild/api/json?tree=number,result,artifacts[fileName,relativePath]" | jq '{number, result, artifacts}'
```

On the checked deployment, this returns build `1`, result `SUCCESS`, and `artifacts: []`. Check the documented download URL's current status:

```bash
curl --max-time 8 -sS -o /dev/null -w 'docker-config.json HTTP %{http_code}\n' "http://203.0.3.36:8080/job/pul-firmware-build/lastSuccessfulBuild/artifact/deploy-bundle/docker-config.json"
```

The current result is HTTP 404. Jenkins is reachable, but the artifact step cannot be completed. The API result does not establish whether the artifact was never published or was later removed. Restore or republish it through the lab Jenkins setup before capturing a current artifact-download screenshot. Do not use a previously downloaded local copy as evidence that the live Jenkins artifact is available.

The older screenshots showing the job artifact and its credential fields have been removed because they do not match the current build state. M2's registry read API is independently accessible without the M1 credential.

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Initial Access | Exploit Public-Facing Application | T1190 |
| Credential Access | Unsecured Credentials: Credentials in Files | T1552.001 |
| Discovery | Network Service Discovery | T1046 |
| Collection | Data from Local System | T1005 |

## Notes for Operator

The public Jenkins API response reports `useSecurity: false`. On the host, `config.xml` has `useSecurity=true` but uses `SecurityRealm$None` and `AuthorizationStrategy$Unsecured`, so the flag does not indicate that access is protected. Live verification on 2026-11-03 confirmed HTTP 200 for the anonymous API and no artifacts on the successful build.
