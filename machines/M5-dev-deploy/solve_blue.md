# solve_blue.md — M5 · dev-deploy
## Blue Team Detection & Response
**Vulnerability:** Dry-run API returned a Kubernetes manifest containing a ServiceAccount token

---

## Detection

Run on the Deploy Commander host:

```bash
grep --color=never 'DRYRUN_MANIFEST_RETURNED' /var/log/pul-deploy/deploy.log | grep -v '127.0.0.1' || printf 'No dry-run manifest events in this log.\n'
```

To show the observed Kali client's events only:

```bash
grep --color=never 'DRYRUN_MANIFEST_RETURNED' /var/log/pul-deploy/deploy.log | grep '10.200.0.8' || printf 'No dry-run manifest events from 10.200.0.8.\n'
```

Both searches were verified against this host; the log records `pul-ota-firmware` dry-run responses containing a ServiceAccount token from `10.200.0.8`.

### Kubernetes API availability

Run these on the Kubernetes host (`203.0.2.188`) to confirm the API service and its source filter are active:

```bash
sudo systemctl is-active k3s k3s-api-source-filter.service
```

```bash
sudo ss -lntp | grep ':6443' || printf 'Kubernetes API is not listening on port 6443.\n'
```

```bash
sudo k3s kubectl get nodes -o wide
```

```bash
sudo k3s kubectl get pods -n pul-production
```

The source filter allows the Kali client (`10.200.0.8`) and Deploy Commander (`203.0.3.36`) to reach port 6443. The service unit reapplies those rules after a reboot.

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

Revoke the exposed Deploy Commander token and rotate the Kubernetes ServiceAccount credential using the configured control planes. The lab cluster is provisioned at `203.0.2.188:6443` in namespace `pul-production`. Its `pul-ota-deployer` ServiceAccount has namespace-scoped read access; the API firewall allows the observed Kali source and Deploy Commander host. The M5 dry-run response still exposes the ServiceAccount token, so rotation must be paired with removing credentials from that response.

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
| Cluster at risk | `203.0.2.188:6443`, namespace `pul-production` |
