# solve_blue.md — M5 · dev-deploy
## Blue Team Detection & Response
**Vulnerability:** Dry-run API returned a Kubernetes manifest containing a ServiceAccount token

---

## Detection

Run on the Deploy Commander host:

```bash
grep --color=never 'DRYRUN_MANIFEST_RETURNED' /var/log/pul-deploy/deploy.log | grep -v '127.0.0.1'
```

To show the observed Kali client's events only:

```bash
grep --color=never 'DRYRUN_MANIFEST_RETURNED' /var/log/pul-deploy/deploy.log | grep '10.200.0.8'
```

Both searches were verified against this host; the log records `pul-ota-firmware` dry-run responses containing a ServiceAccount token from `10.200.0.8`.

### Snort rule example

This is an IDS rule, not a shell command. It assumes the sensor has `$HOME_NET` and HTTP inspection configured:

```text
alert http any any -> $HOME_NET 8888 (
  msg:"GRIDFALL:Deploy Commander dry-run manifest request";
  content:"POST"; http_method; content:"/sync"; http_uri;
  content:"dryRun=true"; http_uri;
  sid:3000501; rev:1;
)
```

## Containment

On the Deploy Commander host, block the observed source from port 8888. Replace the source IP if the log shows a different client:

```bash
sudo iptables -I INPUT 1 -s 10.200.0.8 -p tcp -m tcp --dport 8888 -j DROP
sudo iptables -C INPUT -s 10.200.0.8 -p tcp -m tcp --dport 8888 -j DROP
```

To remove that rule and restore access:

```bash
sudo iptables -D INPUT -s 10.200.0.8 -p tcp -m tcp --dport 8888 -j DROP
```

Revoke the exposed Deploy Commander token and rotate the Kubernetes ServiceAccount credential using the configured control planes. The original cluster address `193.x.x.x` is a placeholder, and the writeup omits the cluster context and namespace; do not use it as a command target.

## Eradication and remediation

1. Remove ServiceAccount tokens and Secrets from dry-run responses.
2. Rotate ServiceAccount credentials that may have appeared in responses.
3. Restrict the deployer ServiceAccount with namespace-scoped least-privilege RBAC.
4. Audit Deploy Commander logs for dry-run requests and review affected cluster audit logs.

## IOC Summary

| Type | Value |
|---|---|
| API called | `POST /api/applications/pul-ota-firmware/sync?dryRun=true` |
| Exposed credential | Deploy Commander token and Kubernetes ServiceAccount token; values redacted |
| Observed source | `10.200.0.8` |
| Root cause | Dry-run API returned a manifest containing a ServiceAccount token |
| Cluster at risk | Cluster endpoint must be confirmed; original address was a placeholder |
