# Remediation Core

Provider-agnostic dependency remediation engine distributed as a pinned CLI release. The initial implementation targets npm direct dependencies and runs without Git provider credentials.

## Current Scope

- Syft SBOM generation.
- Grype vulnerability scan parsing.
- npm direct dependency detection.
- minimum-safe version selection.
- package update through `npm install PACKAGE@VERSION --save-exact --ignore-scripts`.
- target-specific verification and changed-file allowlist.
- structured `result.json` output.

## Compatibility

| Security Workflows | Remediation Core | Status |
| --- | --- | --- |
| v1.0.0 | v0.1.1 | Planned |

## CLI Usage

```bash
go run ./cmd/remediate \
  --directory . \
  --ecosystem auto \
  --minimum-severity high \
  --strategy minimum-safe \
  --allow-major=false \
  --maximum-updates 1 \
  --artifact-directory reports \
  --output result.json
```

Required tools at runtime:

- `syft`
- `grype`
- `npm`
- `git`

When `--artifact-directory` is set, the engine preserves:

- `sbom.before.json`
- `sbom.before.cdx.json`
- `findings.before.json`
- `sbom.after.json`
- `sbom.after.cdx.json`
- `findings.after.json`

## Result Contract

The CLI writes a JSON document matching `schemas/result.schema.json`. A verified update has this status:

```json
{
  "status": "VERIFIED_UPDATE",
  "ecosystem": "npm",
  "directory": "."
}
```

## CI-Driven Testing

The canonical verification path is GitHub Actions. The CI workflow runs unit tests, builds the CLI, executes the npm remediation fixture with Syft and Grype, and uploads the before/after SBOM and scan reports.

## CLI Release

Tagged releases publish Linux CLI binaries:

- `remediate-linux-amd64`
- `remediate-linux-arm64`
- `checksums.txt`

`security-workflows` downloads the pinned release asset instead of building `remediation-core` from source on every run.

Use `v0.1.1` or newer for quiet Syft directory scans with explicit source metadata.

Release notes can be stored in `docs/releases/<tag>.md`; the release workflow uses that file when creating or updating the GitHub Release.

## Current Integration

`security-workflows` invokes this project as:

```text
GitHub Release: opsbento/remediation-core v0.1.1
Asset: remediate-linux-amd64
```

Syft, Grype, Node.js, and npm are prepared by the workflow repository. This keeps remediation-core focused on dependency analysis, update, and verification.
