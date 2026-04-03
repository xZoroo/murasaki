# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in murasaki, **please do not open a public issue.**

Instead, report it privately through one of these channels:

1. **GitHub Security Advisories** (preferred):
   [Create a new advisory](https://github.com/xZoroo/murasaki/security/advisories/new)

2. **Email**: Reach out via the contact information on the [@xZoroo GitHub profile](https://github.com/xZoroo)

### What to Include

- A description of the vulnerability and its potential impact
- Steps to reproduce the issue
- Any relevant logs, screenshots, or proof-of-concept code

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial assessment**: Within 7 days
- **Fix or mitigation**: Depends on severity, but high/critical issues are prioritized immediately

### Scope

The following are in scope for security reports:

- Vulnerabilities in murasaki's code that could lead to unintended behavior
- Dependencies with known CVEs that affect murasaki's functionality
- Issues that could cause murasaki to leak sensitive information (e.g., API keys, credentials)

The following are **out of scope**:

- Security issues in third-party services (AWS Bedrock, Anthropic API, MITRE ATT&CK)
- Misuse of the tool for unauthorized testing (see the [legal disclaimer](README.md#legal-disclaimer))

## Responsible Disclosure

We follow a coordinated disclosure process. We ask that you:

- Allow reasonable time for us to address the issue before public disclosure
- Avoid exploiting the vulnerability beyond what is necessary to demonstrate it
- Do not access or modify other users' data

Thank you for helping keep murasaki and its users safe.
