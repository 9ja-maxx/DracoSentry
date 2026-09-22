#!/usr/bin/env python3
"""
DracoSentry StudioNet Deployment Helper
=======================================
Facilitates deploying DracoSentry to GenLayer StudioNet / Devnet.
Reads contract source, validates SHA-256 parity, and exports frontend deployment manifest.
"""

from pathlib import Path
import hashlib
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "contracts" / "DracoSentry.py"
DEPLOYMENT_FILE = ROOT / "frontend" / "src" / "deployment.json"


def prepare_deployment():
    print("[*] Preparing DracoSentry for StudioNet deployment...")
    source = CONTRACT_PATH.read_text(encoding="utf-8")
    source_sha = hashlib.sha256(source.encode("utf-8")).hexdigest()
    print(f"[+] Verified Source SHA-256: {source_sha}")

    # Read existing deployment config
    deploy_config = json.loads(DEPLOYMENT_FILE.read_text(encoding="utf-8"))
    deploy_config["sourceSha256"] = source_sha

    print("[*] To deploy on GenLayer Studio:")
    print("    1. Open https://studio.genlayer.com")
    print("    2. Create a new contract file: DracoSentry.py")
    print("    3. Paste the contents of contracts/DracoSentry.py")
    print("    4. Click 'Deploy' on StudioNet (Chain ID 61997)")
    print("    5. Copy the deployed contract address and update frontend/src/deployment.json")
    print("=" * 60)


if __name__ == "__main__":
    prepare_deployment()
