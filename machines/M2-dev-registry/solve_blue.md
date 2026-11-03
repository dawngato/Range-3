# solve_blue.md — M2 · dev-registry
## Blue Team Detection & Response
**Vulnerability:** Unauthenticated Docker Registry v2 API and credentials embedded in an image

---

## Detection

Run on the registry host:

```bash
grep --color=never -E 'v2/_catalog|manifests|blobs' /var/log/pul-registry/registry.log | grep -v '127.0.0.1'
```

This host logs client IPs in the registry log. The observed Kali source was `10.200.0.8`; to show its requests only:

```bash
grep --color=never -E 'v2/_catalog|manifests|blobs' /var/log/pul-registry/registry.log | grep '10.200.0.8'
```

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

To remove that rule and restore access:

```bash
sudo iptables -D INPUT -s 10.200.0.8 -p tcp -m tcp --dport 5000 -j DROP
```

The original `htpasswd` commands are not valid remediation for this host as written. The registry runs as the custom `pul-registry.service` Python app; `htpasswd` and `/opt/pul-registry/htpasswd` are absent, and creating a password file alone would not enable authentication. Inspect the running service before implementing an authentication change:

```bash
systemctl status pul-registry.service --no-pager
systemctl show --value -p ExecStart pul-registry.service
```

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
