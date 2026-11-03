# Screenshot audit

This audit covers the local `screenshots/blue/m1` through `m5` files and screenshot links embedded in the machine writeups.

## Local Blue output images

The five `blue_detection_output.png` files show relevant command output and each depicts a successful log query:

| Machine | Output shown | Screenshot status |
|---|---|---|
| M1 | Jenkins access log contains `GET /api/json` from `10.200.0.8` | Command output is relevant; image is a rendered card, not a raw desktop screenshot |
| M2 | Registry catalog, manifest, and blob requests | Command output is relevant; image is a rendered card, not a raw desktop screenshot |
| M3 | Public bucket listing and object download events | Command output is relevant; image is a rendered card, not a raw desktop screenshot |
| M4 | Sonar project settings queries | Command output is relevant; image is a rendered card, not a raw desktop screenshot |
| M5 | Deploy Commander dry-run events | Command output is relevant; image is a rendered card, not a raw desktop screenshot |

Each image itself says it was rendered from SSH output and is not a raw desktop screenshot. Do not submit these five images as genuine terminal screenshots. The M2–M5 images also show log dates from Nov 2, 2026; M1 shows Nov 3, 2026. Capture fresh terminal screenshots for evidence that must correspond to the current run.

## Screenshots embedded in the machine writeups

- The 24 image links in the M1–M4 Blue writeups resolve to PNGs. The reviewed images show terminal commands and output; no broken links were found.
- M5 Blue currently has no embedded screenshot.
- The M5 Red Step 1 screenshot showed the old `193.x.x.x:6443` destination and `11.x.x.x:5000` image registry. It is stale after M5 was connected to the live cluster and registry.
- The M5 Red Step 2 screenshot shows a successful dry-run response. It remains useful only as evidence that the API responded; it does not show the current cluster endpoint.
- The M5 Red Step 3 screenshot showed the old `193.x.x.x:6443` endpoint. It is stale and should be retaken if endpoint evidence is needed.

No command failure is visible in the five local Blue output images. Their issue is screenshot authenticity and, for some images, age—not a failed detection query.
