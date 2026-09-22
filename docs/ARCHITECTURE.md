# Nidhogg Architecture & Technical Design

## 1. System Philosophy & Purpose

Software supply chain vulnerabilities often manifest not through complex zero-day exploits, but through silent license violations, omitted attributions, and unverified package updates. When commercial software vendors release products containing open-source components, they face legal obligations under permissive (e.g. MIT, BSD, Apache) and reciprocal copyleft (e.g. GPL, AGPL) licenses to provide accurate copyright notices.

Historically, this verification has been:
1. **Centralized & Private:** Handled by closed-source proprietary software scanning tools (FOSSA, Snyk, Black Duck) that operate as black boxes.
2. **Easily Forged:** Software distributors can claim compliance without public verification, or selectively omit problematic copyleft packages.

**Nidhogg** solves this by establishing a decentralized, unalterable release notarization protocol on GenLayer.

---

## 2. In-Depth Consensus Architecture

```
[Maintainer / Auditor]
       │
       ▼ (register_release_audit)
┌─────────────────────────────────────────────────────────────┐
│                      Nidhogg Contract                       │
│  - Records Repository, Commit SHA, File Paths & Digests     │
│  - Status: REGISTERED                                       │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼ (execute_consensus_assessment)
┌─────────────────────────────────────────────────────────────┐
│               GenLayer Non-Deterministic Consensus           │
│                 (gl.vm.run_nondet_unsafe)                   │
├──────────────────────────────┬──────────────────────────────┤
│         Leader Node          │       Validator Node         │
│  1. Fetch Raw GitHub Artifact│  1. Fetch Raw GitHub Artifact│
│  2. Verify SHA-256 Bit-Exact │  2. Verify SHA-256 Bit-Exact │
│  3. LLM Micro-Classification │  3. LLM Micro-Classification │
│  4. Emit Observation JSON    │  4. Emit Observation JSON    │
└──────────────────────────────┴──────────────────────────────┘
                               │
                               ▼ (Consensus Equivalence Check)
┌─────────────────────────────────────────────────────────────┐
│              Deterministic Precedence Derivation             │
│  - Verify leader == validator normalized observation JSON   │
│  - Derive terminal verdict from precedence hierarchy         │
│  - Status: FINALIZED (Immutable state persisted)             │
└─────────────────────────────────────────────────────────────┘
```

### 2.1 The Two-Phase Observation Invariant
1. **Phase A: Cryptographic Pre-Gating:**
   Before invoking the LLM, both the leader and validator nodes hash the retrieved bytes using `hashlib.sha256`. If the computed hash differs from the maintainer's registered commitment, the observation immediately aborts into `DIGEST_MISMATCH`. This guarantees that the LLM is never exposed to tampered or poisoned payloads.
2. **Phase B: Quarantined Micro-Classification:**
   The prompt enforces that the AI model acts purely as a semantic comparator. It receives the parsed SBOM packages and the notice text, and must output exactly one pipe-delimited line of tokens.

---

## 3. Storage & Gas Considerations

All storage fields in `Nidhogg.py` utilize GenLayer's typed `TreeMap` primitives:
- `registrations`: Stores immutable release metadata indexed by `u256` audit ID.
- `release_commit_registry`: Composite key mapping (`repo|commit|sbom_sha|notice_sha`) prevents duplicate audit spam.
- `successor_links_plus_one`: One-way pointer linking historical deficit audits to authorized remediation releases.
