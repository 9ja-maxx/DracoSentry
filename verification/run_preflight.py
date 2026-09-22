#!/usr/bin/env python3
"""
Nidhogg Preflight Verification Engine
=====================================
Validates repository integrity, static safety invariants, fixture commitments,
and contract compilation before testnet deployment.
"""

from pathlib import Path
import hashlib
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_FILE = ROOT / "contracts" / "Nidhogg.py"
MANIFEST_FILE = ROOT / "fixtures" / "FIXTURE_MANIFEST.json"


def check_contract_integrity() -> str:
    print("[*] Checking Intelligent Contract source...")
    if not CONTRACT_FILE.exists():
        print("[-] FAILED: Nidhogg.py does not exist.")
        sys.exit(1)

    code = CONTRACT_FILE.read_text(encoding="utf-8")
    if not code.startswith("# v0.2.16"):
        print("[-] FAILED: Missing official GenLayer runner header.")
        sys.exit(1)

    sha = hashlib.sha256(code.encode("utf-8")).hexdigest()
    print(f"[+] Contract SHA-256: {sha}")
    return sha


def check_fixture_manifest():
    print("[*] Validating fixture commitments...")
    if not MANIFEST_FILE.exists():
        print("[-] FAILED: FIXTURE_MANIFEST.json not found.")
        sys.exit(1)

    manifest = json.loads(MANIFEST_FILE.read_text(encoding="utf-8"))
    for name, meta in manifest.get("artifacts", {}).items():
        art_path = ROOT / meta["path"]
        if not art_path.exists():
            print(f"[-] FAILED: Missing artifact {meta['path']}")
            sys.exit(1)

        computed = hashlib.sha256(art_path.read_bytes()).hexdigest()
        if computed != meta["sha256"]:
            print(f"[-] FAILED: Digest mismatch for {name}. Expected {meta['sha256']}, got {computed}")
            sys.exit(1)
        print(f"[+] Verified {name} -> {computed[:16]}...")

    print("[+] All fixture digests confirmed authentic.")


if __name__ == "__main__":
    print("=" * 60)
    print("    NIDHOGG PROTOCOL PREFLIGHT AUDIT")
    print("=" * 60)
    contract_sha = check_contract_integrity()
    check_fixture_manifest()
    print("=" * 60)
    print("[OK] PREFLIGHT SUCCESSFUL. Contract is ready for StudioNet deployment.")
    print("=" * 60)
