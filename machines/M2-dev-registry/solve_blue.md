# solve_blue.md — M2 · dev-registry
## Blue Team Detection & Response
**Vulnerability:** Unauthenticated Docker Registry v2 API and credentials embedded in an image

---

## Detection

Run on the registry host:

```bash
grep --color=never -E 'v2/_catalog|manifests|blobs' /var/log/pul-registry/registry.log | grep -v '127.0.0.1' || printf 'No matching registry API requests in this log.\n'
```
<img width="1461" height="620" alt="WindowsTerminal_32GBFVWdnR" src="https://github.com/user-attachments/assets/f1e35058-5e7f-41cf-9fc8-07433a59c3f6" />

This host logs client IPs in the registry log. The observed Kali source was `10.200.0.8`; to show its requests only:

```bash
grep --color=never -E 'v2/_catalog|manifests|blobs' /var/log/pul-registry/registry.log | grep '10.200.0.8' || printf 'No matching registry requests from 10.200.0.8.\n'
```
<img width="1460" height="617" alt="WindowsTerminal_y8sJbu9VUA" src="https://github.com/user-attachments/assets/d1c0e3bb-5743-4466-a3ae-e83096e0ebfb" />

The query was verified against this host and returned catalogue, manifest, and blob requests from that source.

### Snort rule example

This is an IDS rule, not a shell command. It assumes the sensor has `$HOME_NET` and HTTP inspection configured:

```text
alert http any any -> $HOME_NET 5000 (
  msg:"GRIDFALL:Docker registry catalog enumeration";
  content:"GET"; http_method; content:"/v2/_catalog"; http_uri;
  content:!"Authorization"; http_header;
  sid:3000201; rev:1;
)
```

## Containment

On the registry host, block the observed source from port 5000. Replace the source IP if the log shows a different client:

```bash
sudo iptables -I INPUT 1 -s 10.200.0.8 -p tcp -m tcp --dport 5000 -j DROP
sudo iptables -C INPUT -s 10.200.0.8 -p tcp -m tcp --dport 5000 -j DROP
```
<img width="1441" height="100" alt="WindowsTerminal_GAavSj8S4z" src="https://github.com/user-attachments/assets/3cc7a52d-fc6f-4f26-a982-496a512c7b95" />

To remove that rule and restore access:

```bash
sudo iptables -D INPUT -s 10.200.0.8 -p tcp -m tcp --dport 5000 -j DROP
```
<img width="1325" height="63" alt="WindowsTerminal_vwOh7q9kKR" src="https://github.com/user-attachments/assets/9846d57b-2de9-43d2-af3d-0922c677c9e6" />

The original `htpasswd` commands are not valid remediation for this host as written. The registry runs as the custom `pul-registry.service` Python app; `htpasswd` and `/opt/pul-registry/htpasswd` are absent, and creating a password file alone would not enable authentication. Inspect the running service before implementing an authentication change:

```bash
systemctl status pul-registry.service --no-pager
systemctl show --value -p ExecStart pul-registry.service
```
<img width="1449" height="362" alt="WindowsTerminal_8vAO38IXPo" src="https://github.com/user-attachments/assets/d2005b09-6313-4e5f-924e-621ee83a67d9" />

## Eradication and remediation

1. Rotate the MinIO credentials found in the exposed image; treat both values as compromised.
2. Rebuild and republish the image without credentials in its environment or layers.
3. Implement and verify authentication in the registry application or its configured reverse proxy before reopening external access.
4. Scan all registry images for embedded credentials.

The service configuration does not identify a supported authentication mechanism, so the former `apt-get`/`htpasswd` block has been removed instead of presenting an ineffective command as a fix.

## IOC Summary

| Type | Value |
|---|---|
| Exposed credential | MinIO access key and secret in the image; values redacted |
| Observed source | `10.200.0.8` |
| Root cause | Credentials baked into a Docker image environment layer |
| Next at risk | M3 dev-artifacts, port 9000 |
