# Screenshot audit

This audit covers local `screenshots/blue/m1` through `m5` files and screenshot links embedded in the machine writeups.

## Local Blue output images

The five `blue_detection_output.png` files show relevant command output and each depicts a successful log query:

| Machine | Output shown | Screenshot status |
|---|---|---|
| M1 | Jenkins access log contains `GET /api/json` from `10.200.0.8` | Command output is relevant; image is a rendered card, not a raw desktop screenshot |
| M2 | Registry catalog, manifest, and blob requests | Command output is relevant; image is a rendered card, not a raw desktop screenshot |
| M3 | Public bucket listing and object download events | Command output is relevant; image is a rendered card, not a raw desktop screenshot |
| M4 | Sonar project settings queries | Command output is relevant; image is a rendered card, not a raw desktop screenshot |
| M5 | Deploy Commander dry-run events | Command output is relevant; image is a rendered card, not a raw desktop screenshot |

Each image says it was rendered from SSH output and is not a raw desktop screenshot. Do not submit these five images as genuine terminal screenshots. The M2–M5 images show log dates from Nov 2, 2026; M1 shows Nov 3, 2026. Capture fresh terminal screenshots for evidence that must correspond to the current run.

## Screenshots embedded in the machine writeups

- The 24 image links in the M1–M4 Blue writeups resolve to PNGs. The reviewed images show terminal commands and output; no broken links were found.
- M5 Blue currently has no embedded screenshot.
- The M5 Red screenshots that showed the old `193.x.x.x:6443` destination and `11.x.x.x:5000` image registry were removed after the live endpoint was configured.
- The remaining M5 Red Step 2 screenshot is historical evidence that the API responded; it does not show the current cluster endpoint.
- M1's old job-artifact and credential screenshots were removed because the current Jenkins build reports no archived artifacts.

No command failure is visible in the five local Blue output images. Their issue is screenshot authenticity and, for some images, age—not a failed detection query.

## Live service and screenshot status

Checked from Kali on 2026-11-03. HTTP checks verify service reachability; the read-only API checks verify the current Red writeup path. They do not imply the machines need to be reinstalled.

| Machine | Live result | What to rerun or recapture |
|---|---|---|
| M1 Jenkins | API HTTP 200; `pul-firmware-build` build 1 is `SUCCESS`, but Jenkins reports `artifacts: []`. The documented `docker-config.json` URL returns HTTP 404. | The anonymous API screenshot can be recaptured now. The artifact-download and credential screenshots cannot be recreated until the artifact is restored or republished. |
| M2 Registry | Registry API, catalog, tags, manifest, and config blob returned successfully. | No setup rerun is needed. Recapture the M2 commands if the submission requires fresh terminal screenshots. |
| M3 Artifact store | The documented public bucket listing and `sonarqube-access.env` object returned successfully. A generic MinIO health path tested during triage returned 404; that path is not the documented challenge endpoint. | No setup rerun is needed. Recapture the documented bucket listing and object commands if current screenshots are required. |
| M4 SonarQube | Token validation returned `valid: true`; project settings include the Deploy Commander token key. | No setup rerun is needed. Recapture the validation and settings commands if current screenshots are required. |
| M5 Deploy Commander and cluster | Health check and authenticated dry-run returned successfully. The response names `https://203.0.2.188:6443`; the CA-verified namespace Secret query succeeded. The namespace has no Pods, Deployments, Services, or flag resource. | No setup rerun is needed for the pivot connection. Retake the M5 dry-run and namespace screenshots because older evidence used placeholder endpoints. No flag screenshot is possible until a flag-bearing workload or resource is provisioned. |

None of M1–M5 is simply down. M1 is reachable but its artifact is missing; M2–M5 are reachable and their documented read paths work. For fresh screenshots, rerun M2–M5. For M1, capture the API check now and wait to capture the artifact step until the Jenkins archive is restored. If genuine desktop evidence is required, replace all five local Blue rendered cards with screenshots captured directly from the terminal.
