# solve_blue.md — M4 · dev-sonar
## Blue Team Detection & Response
**Vulnerability:** Plaintext token exposed through the project settings API

---

## Detection

Run on the SonarQube host:

```bash
grep --color=never 'SETTINGS_QUERY' /var/log/pul-sonar/sonar.log | grep -v '127.0.0.1' || printf 'No settings query events in this log.\n'
```
<img width="1329" height="218" alt="WindowsTerminal_pfuhRbXZ0V" src="https://github.com/user-attachments/assets/02ccc61b-6256-477c-a0de-47fff357f2ff" />

To show the observed Kali client's queries only:

```bash
grep --color=never 'SETTINGS_QUERY' /var/log/pul-sonar/sonar.log | grep '10.200.0.8' || printf 'No settings queries from 10.200.0.8.\n'
```
<img width="1267" height="217" alt="WindowsTerminal_LqaInlrQ3b" src="https://github.com/user-attachments/assets/ad915fa3-8faf-4c69-bf36-c70293758906" />

Both searches were verified against this host and returned settings queries for `pul-firmware-ota` from `10.200.0.8`.

### Snort rule example

This is an IDS rule, not a shell command. It assumes the sensor has `$HOME_NET` and HTTP inspection configured:

```text
alert http any any -> $HOME_NET 9200 (
  msg:"GRIDFALL:SonarQube project settings query";
  content:"GET"; http_method; content:"/api/settings/values"; http_uri;
  content:"pul-firmware-ota"; http_uri;
  sid:3000401; rev:1;
)
```

## Containment

On the SonarQube host, block the observed source from port 9200. Replace the source IP if the log shows a different client:

```bash
sudo iptables -I INPUT 1 -s 10.200.0.8 -p tcp -m tcp --dport 9200 -j DROP
sudo iptables -C INPUT -s 10.200.0.8 -p tcp -m tcp --dport 9200 -j DROP
```
<img width="1246" height="83" alt="WindowsTerminal_Br9FywGpwj" src="https://github.com/user-attachments/assets/0f620921-397d-4e34-8fef-45fffc439e45" />

To remove that rule and restore access:

```bash
sudo iptables -D INPUT -s 10.200.0.8 -p tcp -m tcp --dport 9200 -j DROP
```
<img width="1322" height="44" alt="WindowsTerminal_sWAnu2tTJC" src="https://github.com/user-attachments/assets/4456bbf5-3828-479f-b8ec-64a4a41d6ea3" />

Revoke the exposed SonarQube token and the Deploy Commander token through their configured administrative interfaces. Their secret values are intentionally redacted in this public writeup.

## Eradication and remediation

1. Remove `sonar.ci.deploy_token` from project settings and inject it at runtime from the configured secrets manager.
2. Rotate the SonarQube and Deploy Commander tokens that may have been exposed.
3. Add secret scanning for project settings and API responses.
4. Review SonarQube access logs for other settings API requests.

## IOC Summary

| Type | Value |
|---|---|
| Exposed token | Deploy Commander API token in project settings; value redacted |
| Observed source | `10.200.0.8` |
| Root cause | CI/CD token stored as a plaintext project setting |
| Next at risk | M5 dev-deploy, port 8888 |
