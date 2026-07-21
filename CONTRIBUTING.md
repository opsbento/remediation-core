# Contributing

This repository contains the provider-agnostic remediation engine. Keep provider orchestration, Pull Request creation, and credential handling outside this repository.

## Verification

Use GitHub Actions as the primary verification path. The repository CI runs unit tests, builds the CLI, runs the npm remediation fixture, and uploads remediation evidence artifacts.

## Design Rules

- Keep ecosystem-specific behavior behind `internal/ecosystems`.
- Do not run package lifecycle scripts during remediation.
- Do not add GitHub or GitLab API dependencies to core.
- Verify target findings after an update before reporting success.
- Reject unexpected file changes.
