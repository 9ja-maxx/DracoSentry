# Nidhogg Live Lifecycle Verification Matrix

This matrix documents the 20 distinct lifecycle execution paths designed for StudioNet live testing upon deployment:

| # | Phase / Scenario | Expected Contract Verdict | Security Invariant Verified |
|---:|:---|:---|:---|
| 1 | Non-pinned branch name (`main`) | `INVALID_SOURCE_IDENTIFIERS` | Prevents branch tag drift; requires 40-char commit SHA |
| 2 | Path traversal attempt (`../sbom.json`) | `INVALID_SOURCE_IDENTIFIERS` | Prevents file system escape & SSRF |
| 3 | Colliding artifact paths | `COLLIDING_ARTIFACT_PATHS` | Rejects identical paths for SBOM and notice |
| 4 | Register initial complete release | Audit ID `0` (`REGISTERED`) | Authoritative state registration |
| 5 | Duplicate release registration | `DUPLICATE_RELEASE_REGISTRATION` | Prevents replay and registry pollution |
| 6 | Execute complete release assessment | `VERIFIED_COMPLIANT` | Happy-path consensus; 100% compliance score |
| 7 | Assessment replay attempt on Audit `0` | `AUDIT_ALREADY_FINALIZED` | Strict replay prevention on finalized records |
| 8 | Register release with permissive gap | Audit ID `1` (`REGISTERED`) | Captures missing notice fixture |
| 9 | Assess permissive gap release | `ATTRIBUTION_DEFICIT` | Identifies missing attribution with 75% score |
| 10 | Register release with copyleft conflict | Audit ID `2` (`REGISTERED`) | Captures license conflict fixture |
| 11 | Assess copyleft conflict release | `HIGH_RISK_LICENSE_VIOLATION` | High-priority license conflict detection |
| 12 | Register false/tampered SHA-256 digest | Audit ID `3` (`REGISTERED`) | Simulates poisoned artifact digest |
| 13 | Assess tampered release | `TAMPER_DETECTED` | Pre-inference hash mismatch fail-closed |
| 14 | Register unavailable/dead GitHub path | Audit ID `4` (`REGISTERED`) | Simulates transient 404 or network outage |
| 15 | Assess unavailable source | `AUDIT_RETRYABLE` | Leaves status in `REGISTERED` for retry |
| 16 | Register remediation release on new commit | Audit ID `5` (`REGISTERED`) | Successor commit candidate |
| 17 | Assess remediation release | `VERIFIED_COMPLIANT` | Remediation passes consensus |
| 18 | Unauthorized outsider remediation attempt | `UNAUTHORIZED_CREATOR_ONLY` | Enforces creator signature on remediation link |
| 19 | Creator remediation linking | `REMEDIATION_BOUND` | Immutably binds Audit `1` -> Audit `5` |
| 20 | Remediation double-link attempt | `REMEDIATION_ALREADY_BOUND` | Prevents overwriting successor references |
