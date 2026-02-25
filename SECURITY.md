# Security Policy

SeaCore is a security-sensitive proxy system. This document defines how vulnerabilities are reported, triaged, fixed, and disclosed.

## Supported Versions

| Version line | Security fixes |
| --- | --- |
| `main` branch | Yes |
| Latest release tag | Yes |
| Older release tags | Best effort only |

If you run an older release, upgrade to the latest version before filing a security report unless the upgrade itself is blocked by the issue.

## Reporting a Vulnerability

Please do **not** open a public issue for an active vulnerability.

Preferred channel:
1. GitHub Security Advisory private report (if enabled for this repository).
2. If private reporting is not available, open a minimal issue asking maintainers to establish a private channel first, without exploit details.

Include:
- affected version/commit
- deployment mode (`tcp`/`udp`/`auto`)
- minimal reproduction steps
- expected impact (auth bypass, info leak, DoS, probing signal, etc.)
- logs/pcap snippets with sensitive data removed

## Triage and Response Targets

- Acknowledge report: within 72 hours
- Initial severity and impact assessment: within 7 days
- Patch target:
  - Critical: 7 days
  - High: 14 days
  - Medium: 30 days
  - Low: next scheduled release

These are operational targets, not hard guarantees.

## Disclosure Process

1. Reproduce and confirm impact.
2. Prepare and review patch.
3. Add/extend regression tests.
4. Release fixed version.
5. Publish advisory with remediation guidance.

Coordinated disclosure is preferred: details are published after a fix is available.

## Upgrade and Dependency Baseline

- Rust toolchain: keep on current stable channel.
- Runtime crypto/network dependencies (`rustls`, `quinn`, `ring`, `tokio`) should be updated in regular maintenance windows.
- Security-relevant dependency updates should include a changelog review and regression test run (`cargo test` + `Test/test_matrix.py`).

## Insecure Configuration Denylist

The following are disallowed in production deployments:

- `insecure_skip_verify = true` without strict temporary exception scope.
- Exposing `metrics_listen` to public internet without network ACL/firewall.
- Weak/shared credentials across tenants (`uuid`, `password`).
- Missing REALITY validation inputs (`public_key`, valid 8-byte `short_id`).
- Running Internet-facing services without resource limits (`max_*` caps, process limits).

Temporary exceptions for local debugging must be documented and time-bounded.

## Scope Notes

- Test scripts may intentionally use insecure settings (for example self-signed cert acceptance) to keep local CI deterministic.
- Those test-only settings must not be copied into production config templates.
