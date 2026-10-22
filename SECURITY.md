# Security policy

## Reporting a vulnerability

Please report security issues privately through GitHub's "Report a vulnerability"
(security advisories) on this repository rather than in a public issue. Include steps
to reproduce and the affected version. You should get an acknowledgement within a week.

## Scope and design notes

VulnTriage is designed to run inside a private homelab. See "Security considerations"
in the [README](README.md) for the trust model: Docker socket access through a GET-only
proxy, the network-scan allow-list, LAN-only dashboard, and the handling of secrets and
scan data.
