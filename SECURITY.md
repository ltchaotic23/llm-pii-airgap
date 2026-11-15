# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability, regex bypass, or false-negative leak path in `llm-pii-airgap`, please **do not** open a public GitHub issue with working bypass payloads against live credentials.

Instead, report it privately via one of the following channels:

1. **GitHub Security Advisories**: Submit a private advisory directly under this repository's **Security -> Advisories -> New draft security advisory** tab.
2. **Direct Contact**: See [`https://mailotic.me/.well-known/security.txt`](https://mailotic.me/.well-known/security.txt) for verified PGP contact details.

Please include:
- A minimal, non-sensitive synthetic input demonstrating the bypass or leak condition.
- Expected redaction/tokenisation behaviour vs. observed output.
- Python version and OS details if platform-specific.
