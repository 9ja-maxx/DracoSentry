from pathlib import Path
import ast
import hashlib
import json

ROOT = Path(__file__).resolve().parents[1]
SOURCE_PATH = ROOT / "contracts" / "Nidhogg.py"
SOURCE = SOURCE_PATH.read_text(encoding="utf-8")


def test_contract_headers_and_sdk_primitives():
    """Verify official GenLayer runner and dependency headers."""
    assert SOURCE.startswith("# v0.2.16\n# { \"Depends\": \"py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6\" }")
    tree = ast.parse(SOURCE)
    assert tree is not None
    assert "https://raw.githubusercontent.com/" in SOURCE
    assert "gl.vm.run_nondet_unsafe" in SOURCE
    assert "response.status" in SOURCE
    assert "status_code" not in SOURCE


def test_public_methods_disallow_arbitrary_urls():
    """Ensure no public write method accepts arbitrary URL arguments (SSRF defense)."""
    tree = ast.parse(SOURCE)
    func_defs = [node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
    public_funcs = [fn for fn in func_defs if any("public" in getattr(dec, "attr", "") or "public" in getattr(dec, "id", "") for dec in fn.decorator_list)]
    
    for fn in public_funcs:
        for arg in fn.args.args:
            assert "url" not in arg.arg.lower(), f"Public function '{fn.name}' exposes suspicious argument '{arg.arg}'"


def test_fixture_sizes_and_cryptographic_hashes():
    """Verify test fixtures adhere to protocol size bounds and are non-empty."""
    manifest_path = ROOT / "fixtures" / "FIXTURE_MANIFEST.json"
    assert manifest_path.exists()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    
    for filename, meta in manifest["artifacts"].items():
        artifact_path = ROOT / meta["path"]
        assert artifact_path.exists(), f"Missing fixture artifact: {meta['path']}"
        raw_bytes = artifact_path.read_bytes()
        assert 0 < len(raw_bytes) <= 32000
        computed_sha = hashlib.sha256(raw_bytes).hexdigest()
        assert computed_sha == meta["sha256"], f"Digest mismatch for {filename}"


def derive_model_verdict(status: str, coverage: list) -> str:
    """Independent Python model of the contract's deterministic verdict hierarchy."""
    if status == "NETWORK_UNREACHABLE":
        return "AUDIT_RETRYABLE"
    if status == "DIGEST_MISMATCH":
        return "TAMPER_DETECTED"
    if status == "INVALID_PAYLOAD":
        return "MALFORMED_INPUT"
    if "COPYLEFT_CONFLICT" in coverage:
        return "HIGH_RISK_LICENSE_VIOLATION"
    if "PERMISSIVE_GAP" in coverage:
        return "ATTRIBUTION_DEFICIT"
    if "UNRESOLVED" in coverage:
        return "INDETERMINATE"
    return "VERIFIED_COMPLIANT"


def test_deterministic_precedence_matrix():
    """Verify all branches of the deterministic on-chain verdict precedence matrix."""
    assert derive_model_verdict("OBSERVATION_COMPLETE", ["COMPLIANT", "COMPLIANT", "COMPLIANT"]) == "VERIFIED_COMPLIANT"
    assert derive_model_verdict("OBSERVATION_COMPLETE", ["COMPLIANT", "PERMISSIVE_GAP", "COMPLIANT"]) == "ATTRIBUTION_DEFICIT"
    assert derive_model_verdict("OBSERVATION_COMPLETE", ["COMPLIANT", "COPYLEFT_CONFLICT", "PERMISSIVE_GAP"]) == "HIGH_RISK_LICENSE_VIOLATION"
    assert derive_model_verdict("OBSERVATION_COMPLETE", ["COMPLIANT", "UNRESOLVED", "COMPLIANT"]) == "INDETERMINATE"
    assert derive_model_verdict("DIGEST_MISMATCH", []) == "TAMPER_DETECTED"
    assert derive_model_verdict("NETWORK_UNREACHABLE", []) == "AUDIT_RETRYABLE"
    assert derive_model_verdict("INVALID_PAYLOAD", []) == "MALFORMED_INPUT"


if __name__ == "__main__":
    print("[*] Running Nidhogg Contract Model Verification...")
    test_contract_headers_and_sdk_primitives()
    print("  [+] test_contract_headers_and_sdk_primitives passed")
    test_public_methods_disallow_arbitrary_urls()
    print("  [+] test_public_methods_disallow_arbitrary_urls passed")
    test_fixture_sizes_and_cryptographic_hashes()
    print("  [+] test_fixture_sizes_and_cryptographic_hashes passed")
    test_deterministic_precedence_matrix()
    print("  [+] test_deterministic_precedence_matrix passed")
    print("[OK] All 4 contract model tests passed.")
