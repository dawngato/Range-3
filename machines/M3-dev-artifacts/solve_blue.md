# solve_blue.md — M3 · dev-artifacts
## Blue Team Detection & Response
**Vulnerability:** Public S3 bucket ACL on `pul-code-reports`

---

## Detection

Run on the artifact-store host:

```bash
grep --color=never -E 'UNAUTH_BUCKET_ACCESS|pul-code-reports' /var/log/pul-artifacts/artifacts.log | grep -v '127.0.0.1' || printf 'No matching bucket access events in this log.\n'
```
<img width="1460" height="703" alt="WindowsTerminal_XZVL0rsxjJ" src="https://github.com/user-attachments/assets/e65a937e-6b52-4dcd-9468-cec425c91091" />

To show the observed Kali client's events only:

```bash
grep --color=never -E 'UNAUTH_BUCKET_ACCESS|pul-code-reports' /var/log/pul-artifacts/artifacts.log | grep '10.200.0.8' || printf 'No matching bucket events from 10.200.0.8.\n'
```
<img width="1454" height="640" alt="WindowsTerminal_9FDrOKZNRV" src="https://github.com/user-attachments/assets/3bdda4d5-270a-42fc-a50f-0638da55de12" />

Both searches were verified against this host; the logs include bucket listing and object download requests from `10.200.0.8`.

### Snort rule example

This is an IDS rule, not a shell command. It assumes the sensor has `$HOME_NET` and HTTP inspection configured:

```text
alert http any any -> $HOME_NET 9000 (
  msg:"GRIDFALL:Public S3 bucket access";
  content:"GET"; http_method; content:"pul-code-reports"; http_uri;
  content:!"Authorization"; http_header;
  sid:3000301; rev:1;
)
```

## Containment

On the artifact-store host, block the observed source from port 9000. Replace the source IP if the log shows a different client:

```bash
sudo iptables -I INPUT 1 -s 10.200.0.8 -p tcp -m tcp --dport 9000 -j DROP
sudo iptables -C INPUT -s 10.200.0.8 -p tcp -m tcp --dport 9000 -j DROP
```
<img width="1273" height="92" alt="WindowsTerminal_5w9dslIcz2" src="https://github.com/user-attachments/assets/738be9b4-77ad-4684-9bdb-306c6fdb8192" />

To remove that rule and restore access:

```bash
sudo iptables -D INPUT -s 10.200.0.8 -p tcp -m tcp --dport 9000 -j DROP
```
<img width="1008" height="44" alt="WindowsTerminal_AbJLLn1u3h" src="https://github.com/user-attachments/assets/c1139660-7b02-4794-a4a2-bcdf6aed4608" />

Set `pul-code-reports` to private using the artifact store's configured administrative interface, then revoke the exposed SonarQube token. The writeup does not identify an admin CLI or provide a verified credential-rotation endpoint, so those operations must be done through the configured control planes.

## Eradication and remediation

1. Remove public access from all buckets and review bucket ACLs.
2. Rotate the exposed SonarQube token; its value is redacted here because this writeup is public.
3. Remove `sonarqube-access.env` from object storage and rotate any other credentials it contained.
4. Enforce private bucket policies and audit public-access changes.

## IOC Summary

| Type | Value |
|---|---|
| Exposed credential | SonarQube token in `sonarqube-access.env`; value redacted |
| Observed source | `10.200.0.8` |
| Root cause | Public-read access on `pul-code-reports` |
| Next at risk | M4 dev-sonar, port 9200 |
