# Nidhogg CI/CD Integration Guide

Automate release provenance verification in your continuous deployment pipeline before publishing packages to npm, PyPI, or release registries.

## GitHub Actions Release Gate Example

Add this workflow to `.github/workflows/nidhogg-audit.yml`:

```yaml
name: Nidhogg Provenance Verification

on:
  release:
    types: [published]

jobs:
  verify-provenance:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Release Commit
        uses: actions/checkout@v4

      - name: Compute Artifact Digests
        id: digests
        run: |
          SBOM_SHA=$(sha256sum release/sbom.json | awk '{print $1}')
          NOTICE_SHA=$(sha256sum THIRD_PARTY_NOTICES.md | awk '{print $1}')
          echo "sbom_sha=$SBOM_SHA" >> $GITHUB_OUTPUT
          echo "notice_sha=$NOTICE_SHA" >> $GITHUB_OUTPUT

      - name: Register Release on Nidhogg
        env:
          STUDIONET_PRIVATE_KEY: ${{ secrets.STUDIONET_SIGNER_KEY }}
          NIDHOGG_CONTRACT: "0x..."
        run: |
          npx ts-node scripts/register-release.ts \
            --commit ${{ github.sha }} \
            --sbom-path "release/sbom.json" \
            --sbom-sha ${{ steps.digests.outputs.sbom_sha }} \
            --notice-path "THIRD_PARTY_NOTICES.md" \
            --notice-sha ${{ steps.digests.outputs.notice_sha }}

      - name: Assert Verified Compliance
        run: |
          echo "Waiting for GenLayer validator consensus..."
          # Poll get_audit_dossier until FINALIZED and VERIFIED_COMPLIANT
```
