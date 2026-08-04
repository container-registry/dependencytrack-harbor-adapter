# Security Policy

## Reporting a vulnerability

Please report security vulnerabilities privately. Do **not** open a public GitHub
issue for a security report.

- Preferred: GitHub's private "Report a vulnerability" advisory flow on this
  repository (encrypted in transit and at rest, and it keeps the report tied to
  the repo).
- Alternatively, email **security@8gears.com**. Note this channel has no
  published PGP key, so treat it as plain email and keep exploit details for
  the advisory flow when possible.

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
