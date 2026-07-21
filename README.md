# oci-arm-grabber

Grabs a free Oracle Cloud **Ampere A1.Flex** ARM instance the moment capacity
appears — runs 24/7 on GitHub Actions so no local machine needs to stay on.

A single scheduled run loops `LaunchInstance` every 60s for ~5.7h; `concurrency`
queues the next run so coverage is continuous. Public repo → unlimited free
Actions minutes. All OCI/notify config is injected via encrypted **GitHub
Secrets** (never in code). On success it pings a Discord channel.

Not affiliated with Oracle. Personal automation.
