# solve_blue.md — M1 · dev-jenkins
## Blue Team Detection & Response Writeup
**Range:** RNG-DEV-01 · VIKAS TANTRA
**Machine:** M1 — Jenkins CI/CD Server
**Vulnerability:** Jenkins anonymous read access and unauthenticated artifact download
**MITRE ATT&CK:** T1190 · T1552.001

---

## Detection

### Jenkins HTTP access log

HTTP request paths are not recorded by `journalctl` on this host. Jenkins Winstone access logging is enabled and writes requests to `/var/log/jenkins/access_log`.

If the access log is missing on a fresh host, enable it once with these commands. This restarts Jenkins:

```bash
sudo mkdir -p /etc/systemd/system/jenkins.service.d
printf '%s\n' '[Service]' 'Environment="JENKINS_ENABLE_ACCESS_LOG=true"' | sudo tee /etc/systemd/system/jenkins.service.d/access-log.conf >/dev/null
sudo systemctl daemon-reload
sudo systemctl restart jenkins
```
<img width="1452" height="232" alt="WindowsTerminal_xmgqWPO1dV" src="https://github.com/user-attachments/assets/81b034b3-39a2-4a5c-bba0-26d07de3b70b" />

Check the service and log file:

```bash
systemctl is-active jenkins
ls -l /var/log/jenkins/access_log
```
<img width="1288" height="336" alt="WindowsTerminal_0satIR0s75" src="https://github.com/user-attachments/assets/b1ca72dc-6708-4dd9-8222-83f9468adab6" />

To create a test API request, run from Kali:

```bash
curl --max-time 8 -sS -o /dev/null -w 'HTTP %{http_code}\n' http://203.0.3.36:8080/api/json
```
<img width="1029" height="125" alt="WindowsTerminal_nIV7R3BoOJ" src="https://github.com/user-attachments/assets/8ca2e324-764c-4fe2-b367-3d25bdda98b4" />

On the Jenkins host, find API enumeration and artifact downloads:

```bash
grep --color=never -E 'GET /api/json|GET /job/.*/artifact' /var/log/jenkins/access_log
```
<img width="1436" height="479" alt="WindowsTerminal_dtnws1DZOA" src="https://github.com/user-attachments/assets/ab11e847-94de-41ef-87a5-add49b2d7875" />

To show the observed Kali source specifically:

```bash
grep --color=never -E 'GET /api/json|GET /job/.*/artifact' /var/log/jenkins/access_log | grep '10.200.0.8'
```
<img width="1415" height="442" alt="WindowsTerminal_b0FPGR7hCa" src="https://github.com/user-attachments/assets/92a99ad8-a99e-4103-a105-458f4bbb0f79" />

The observed client address was `10.200.0.8`. Check the access log for the current source if it changes. `journalctl -u jenkins --no-pager` shows service messages, not the HTTP request records; startup entries can contain sensitive setup information, so redact them before sharing.

**Anomaly signature:**

- `GET /api/json` with a `tree=` query from an unexpected source
- `GET /job/pul-firmware-build/lastSuccessfulBuild/artifact/` from an unexpected source
- Observed lab source: `10.200.0.8`

### Network IDS

IDS signatures are configuration rules, not shell commands. The original rules use the placeholder host `11.x.x.x`. For this range, the Jenkins address is `203.0.3.36`; install rules only after confirming the sensor and its supported rule syntax.

---

## Containment

List current INPUT rules:

```bash
sudo iptables -L INPUT -n --line-numbers
```
<img width="916" height="121" alt="WindowsTerminal_uz0E3LxtCF" src="https://github.com/user-attachments/assets/847b3bdd-b48b-4e58-bc1a-50077ac28a8b" />

Block the observed Kali source from Jenkins on port 8080:

```bash
sudo iptables -I INPUT 1 -s 10.200.0.8 -p tcp -m tcp --dport 8080 -j DROP
```
<img width="1287" height="70" alt="WindowsTerminal_LEeNLYoCe1" src="https://github.com/user-attachments/assets/e1894d7f-ad5d-40ab-aa69-668bf4844fe6" />

Verify that exact rule is installed:

```bash
sudo iptables -C INPUT -s 10.200.0.8 -p tcp -m tcp --dport 8080 -j DROP
```
<img width="1238" height="87" alt="WindowsTerminal_0OAckUXk57" src="https://github.com/user-attachments/assets/cf7865d1-43a2-4855-aaff-6eaa07970869" />

Remove the rule to restore Jenkins access from Kali:

```bash
sudo iptables -D INPUT -s 10.200.0.8 -p tcp -m tcp --dport 8080 -j DROP
```
<img width="1304" height="141" alt="WindowsTerminal_NRmvMPbes7" src="https://github.com/user-attachments/assets/a2e6ce62-4b61-4fcc-a829-27129324ad82" />

The drop rule blocks Kali from Jenkins on port 8080; SSH on port 22 is unaffected. The original internal-only rule used `11.x.x.x/24`, which is a placeholder. No trusted internal CIDR is specified for this host, so there is no safe copy-paste internal-only rule yet.

### Jenkins authentication

Do not run the original `config.xml.patch` block. It writes a separate patch file and does not apply it to Jenkins. Setting `useSecurity=true` without a provisioned administrator and valid authorization strategy can lock out Jenkins users.

Inspect the current security settings:

```bash
sudo grep -E '<useSecurity>|<securityRealm|<authorizationStrategy' /var/lib/jenkins/config.xml
```
<img width="1453" height="154" alt="WindowsTerminal_WK8jzJNBoY" src="https://github.com/user-attachments/assets/d0ced6e7-509d-460e-95ef-cf9c22eeb792" />

On this host, `useSecurity` is `true`, but the configured realm is `SecurityRealm$None` and the authorization strategy is `AuthorizationStrategy$Unsecured`. Jenkins still returns anonymous API requests successfully, so the `useSecurity` flag alone does not mean access is protected.

Enable authentication through the Jenkins administration process only after a working administrator account and recovery path are confirmed. The writeup does not specify working administrator credentials or an approved realm, so no direct configuration-changing command is provided.

---

## Eradication

The artifact's registry host `11.x.x.x:5000` is a scenario placeholder; the deployed registry is reachable at `203.0.3.36:5000`. Rotate the exposed `pul-registry-svc` credential through the registry's configured control plane. The Vault example is not directly runnable until Vault is configured and a new credential has been issued; do not paste a placeholder password into a command.

After saving required incident evidence and rotating the credential, remove the exposed build archive if eradication is intended. This command deletes the archived artifact:

```bash
sudo rm -rf -- /var/lib/jenkins/jobs/pul-firmware-build/builds/1/archive/
```
<img width="1265" height="57" alt="WindowsTerminal_IA6ZMQshP7" src="https://github.com/user-attachments/assets/d6224d5e-7dcc-4986-b07d-86d68571d1bb" />

Update the Jenkins pipeline to obtain the replacement credential from the configured secrets manager at build time. Do not store it in a build artifact.

---

## Permanent remediation

1. Enable Jenkins authentication with a provisioned administrator and tested authorization strategy.
2. Rotate credentials found in this and other archived builds.
3. Inject CI/CD credentials from the configured secrets manager at build time.
4. Restrict artifact downloads to authorized build operators and administrators.
5. Audit archived artifacts for credentials regularly.
6. Keep Jenkins HTTP access logging enabled and forward it to the central log collector.

---

## IOC Summary

| Type | Value |
|---|---|
| Attack vector | HTTP GET to Jenkins REST API without authentication |
| Endpoints | `/api/json`; `/job/pul-firmware-build/lastSuccessfulBuild/artifact/deploy-bundle/docker-config.json` |
| Observed source | `10.200.0.8` |
| Exposed credential | `pul-registry-svc` credential in `docker-config.json`; treat as compromised and do not reuse |
| Root cause | Jenkins anonymous read access and credential stored in a build artifact |
| Next range at risk | M2 dev-registry, port 5000 |

---

*solve_blue.md | M1 dev-jenkins | RNG-DEV-01 · VIKAS TANTRA | OPERATION GRIDFALL*
