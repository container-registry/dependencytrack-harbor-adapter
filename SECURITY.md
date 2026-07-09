# Security Policy

## Reporting a vulnerability

Please report security vulnerabilities privately. Do **not** open a public GitHub
issue for a security report.

- Email: **security@8gears.com**
- Alternatively, use GitHub's private "Report a vulnerability" advisory flow on
  this repository.

Include a description, affected version, and reproduction steps where possible.
We will acknowledge receipt and coordinate a fix and disclosure timeline with you.

## Supported versions

This project is pre-1.0. Only the latest released minor version receives security
fixes.

## Scope note

The adapter accepts a registry URL and credentials in each scan request and fetches
the referenced artifact on the requester's behalf. Deployments should constrain its
egress (NetworkPolicy), enable API-key authentication where exposed, and never log
credentials. See `docs/` for deployment guidance.
