# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Clampd, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Email: **security@clampd.dev**

Include:
- Description of the vulnerability
- Steps to reproduce
- Affected versions
- Impact assessment (if known)

## Response Timeline

- **Acknowledgment**: within 48 hours
- **Initial assessment**: within 5 business days
- **Fix or mitigation**: depends on severity, typically within 30 days for critical issues

## Scope

In scope:
- ag-gateway, ag-intent, ag-policy, ag-engine, and all runtime services
- SDK libraries (Python, TypeScript)
- CLI tool
- Docker image configurations
- Detection rule bypasses

Out of scope:
- Social engineering attacks against Clampd staff
- Denial of service attacks
- Issues in third-party dependencies (report upstream, but let us know)

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.9.x   | Yes       |
| < 0.9   | No        |

## Recognition

We credit reporters in release notes (with permission). No formal bug bounty program at this time.
