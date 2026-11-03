# solve_blue.md — M4 · dev-sonar
## Blue Team Detection & Response
**Vulnerability:** Plaintext token in project settings API

---
## Detection
```bash
# Check for settings API queries
grep "SETTINGS_QUERY" /var/log/pul-sonar/sonar.log
# Shows: component=pul-firmware-ota from external IP
```
<img width="1765" height="134" alt="image" src="https://github.com/user-attachments/assets/bee06e98-f462-4b4d-8792-92452026bbe5" />


### Snort Rule
```
alert http any any -> 11.x.x.x 9200 (
  msg:"GRIDFALL:SonarQube settings API with external token";
  content:"GET"; http_method; content:"/api/settings/values"; http_uri;
  content:"pul-firmware-ota"; http_uri;
  sid:3000401; rev:1;
)
```

## Containment
1. Revoke `sqa_pul_admin_2024_gridfall` token immediately
2. Revoke `dc-pul-deploy-2024-gridfall` Deploy Commander token
3. Block external access to port 9200

## Eradication
1. **Remove** `sonar.ci.deploy_token` from project settings — store in Vault instead
2. **Regenerate** all project tokens and deploy tokens
3. **Implement** secret scanning on SonarQube project configurations

## IOC Summary
| Type | Value |
|---|---|
| Exposed Token | dc-pul-deploy-2024-gridfall (Deploy Commander API token) |
| Root Cause | CI/CD token stored as plaintext project setting |
| Next at Risk | M5 dev-deploy (11.x.x.x:8888) |
