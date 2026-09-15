# Security Policy

## Supported version

Only the latest commit on `main` is maintained.

## Intended use

This repository is an educational traffic-analysis report. It contains no
intentionally vulnerable service. Raw packet captures are excluded because they
can reveal addresses, hostnames, sessions, and unrelated personal activity.

## Reporting a security issue

Use GitHub private vulnerability reporting when available. Never attach a raw
capture or sensitive packet contents to a public issue. If a published artifact
contains a real secret, revoke and rotate it before repository cleanup.

## Maintainer checks

Before publishing, run `pre-commit run --all-files`, validate every documented
display filter, and confirm that packet captures remain untracked.
