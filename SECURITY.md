# Security Policy

## Supported Versions

| Version | Supported          |
| :------ | :----------------- |
| `0.1.x` | :white_check_mark: |
| `< 0.1` | :x:                |

---

## Threat Model & Boundary Enforcement

`openbao-agent-guard` is built specifically to address the unique threat model of autonomous LLM/AI agents:

- **Prompt Injection & Accidental Exfiltration**: Prevents agents from printing secrets to terminal stdout, reasoning traces, or logs.
- **Accidental Git Commits**: Enforces working-tree verification to block writing credentials to version-controlled directories.
- **Least-Privilege Token Scoping**: Uses short-lived, tightly scoped OpenBao policy tokens.

---

## Reporting a Vulnerability

If you identify a bypass or security issue:

1. Open a **GitHub Security Advisory**: [New Security Advisory](https://github.com/betaucourt/openbao-agent-guard/security/advisories/new)
2. Or contact the maintainer via email: `betaucourt@users.noreply.github.com`

Reports are acknowledged within **48 hours** with a priority triage process.
