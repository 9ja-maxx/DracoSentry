# DracoSentry Pre-Deployment Audit

## Gate Verification Status

- **Contract AST & Static Security Analysis:** Verified passing. Public entry points disallow arbitrary URL ingestion. All paths are sanitized against directory traversal.
- **Direct Mode Test Suite:** 12 comprehensive unit and integration tests covering:
  1. Authoritative registration with slug and 40-character Git commit validation.
  2. SSRF defense and directory traversal interception (`..`, leading slashes).
  3. Duplicate release registration blocking.
  4. Happy-path assessment and validator re-execution (`vm.run_validator() is True`).
  5. Cryptographic digest substitution interception (`TAMPER_DETECTED`).
  6. Permissive attribution deficit detection (`ATTRIBUTION_DEFICIT`).
  7. Copyleft conflict priority enforcement (`HIGH_RISK_LICENSE_VIOLATION`).
  8. Malformed model response fail-closed handling (`INDETERMINATE`).
  9. Validator consequential disagreement rejection.
  10. Replay protection (`AUDIT_ALREADY_FINALIZED`).
  11. Creator-authenticated immutable successor remediation linking.
  12. Unauthorized outsider remediation rejection.

## Cryptographic Commit & Source Hash
- **Contract Source:** `contracts/DracoSentry.py`
- **Source SHA-256:** `5370425d1e30c7803448b9d0b6f04b09683c70b5a1a69c4bc259efc2aba7b551`
- **GenLayer Runner:** `py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6` (v0.2.16)
- **Target Network:** GenLayer StudioNet (Chain ID: `61997`)

## Verified Fixture Commit
- **Repository:** `9ja-maxx/DracoSentry`
- **Artifacts:**
  - `fixtures/sbom-complete.json`: `e5b54ad859fac78d051ef0afd14de452538d8524c6d91d0ffdd1e6530ba74c8a`
  - `fixtures/notice-complete.md`: `4adb9e2995f93b4ec677f740fa75f2a5c4af0e5044525518ac94d8672608a378`
  - `fixtures/notice-permissive-gap.md`: `7b7ce26af806d08bd0f96750984f519c33e42444af57d1df0f6d8db542e26b62`
  - `fixtures/notice-copyleft-conflict.md`: `ae2eb16a748b5c12a3e40b97a7d0003e6094975adfa5240b9fe278ca268a094d`
  - `fixtures/notice-adversarial-injection.md`: `cd832ae205eba4741bf64661aeab0e1020a9d376b7ce8728a54caef9ed5b6c23`
