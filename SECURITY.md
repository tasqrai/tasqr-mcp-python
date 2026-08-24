# Security Policy

## Reporting a vulnerability

Please **do not** open a public issue for a security problem.

Use GitHub's private vulnerability reporting instead: go to the **Security** tab of this repository and choose **Report a vulnerability**. That opens a private channel visible only to the maintainers.

Please include what you were doing, what you observed, and how to reproduce it. We aim to acknowledge reports within a few working days.

## Supported versions

Only the latest released version receives security fixes.

## Scope

This package is a thin local proxy. It holds your Tasqr API key on disk (`0600`) and, when client-side encryption (BYOK) is enabled, handles a data encryption key in memory.

Reports we especially want to hear about:

- Anything that writes key material or plaintext task content to disk or logs.
- Anything that causes task fields to reach the server unencrypted while BYOK is configured.
- Anything that weakens the permissions on the credentials file or the event log.
