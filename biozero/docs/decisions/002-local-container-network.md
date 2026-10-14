# Decision: local container entry

Date: 2026-10-14. Applies to the loopback reviewer/CLI demo only.

The first real Compose run started all four services but failed the host-side
Upload API health deadline. On Docker Engine 29.9.0 ARM64, the sole internal
bridge retained requested HostConfig.PortBindings but NetworkSettings.Ports was
null; no loopback listener existed. A diagnostic request received connection
refused. This was a networking failure, not successful authorization rejection.

Use a project-scoped normal bridge for services that publish loopback entry
ports. Every published port explicitly binds 127.0.0.1, and the bridge also has
127.0.0.1 as its default host-binding address. Keep worker network_mode=none,
individual mTLS API identities, non-root users, bounded resources, read-only
root filesystems and scoped private mounts. This bridge does not enforce an
API/gateway egress deny policy; the gateway uses fixed HTTPS backend URLs.

Docker's [port-publishing documentation](https://docs.docker.com/engine/network/port-publishing/)
defines local bindings. Its [networking overview](https://docs.docker.com/engine/network/)
distinguishes internal and externally connected networks. Actual listener and
HTTP/TLS tests must prove local access and client isolation in each executor.

The failed run is preserved at
`biozero/docs/evidence/20261014T134917-559692Z-reviewer-compose/public/`.
Recreate only the experiment's own Compose project after this change; do not
edit the daemon firewall, use host networking, or alter environment egress policy.
External publishing and production network policy remain separate work.
