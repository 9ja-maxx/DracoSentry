from pathlib import Path
import hashlib
import importlib
import json
import sys
from unittest.mock import patch

from gltest.direct import VMContext, create_address, deploy_contract

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "contracts" / "Nidhogg.py"
COMMIT_A = "1b4fa7cd039c3b62d5444c2b06de19d98f6a0158"
COMMIT_B = "2c5eb8de149d4c73e6555d3c17ef2ae09f7b1269"
POLICY = "Every SBOM package must have matching copyright attribution and declared license in the third-party notice."


def deploy_nidhogg():
    """Deploy Nidhogg within direct VMContext and set up module imports."""
    creator, outsider = create_address("creator"), create_address("outsider")
    vm = VMContext(creator)
    with patch("os.unlink", lambda _path: None):
        with vm.activate():
            contract = deploy_contract(CONTRACT_PATH, vm)
            proxy = contract._instance.register_release_audit.__globals__["gl"]
            _ = proxy.nondet
            _ = proxy.vm
    sdk_root = str(Path(proxy._cached_gl.__file__).resolve().parents[2])
    if sdk_root not in sys.path:
        sys.path.insert(0, sdk_root)
    importlib.import_module("genlayer")
    return vm, contract, creator, outsider


def sync_vm(vm, contract):
    """Synchronize VM context message state with contract proxy."""
    proxy = contract._instance.register_release_audit.__globals__["gl"]
    sdk_root = str(Path(proxy._cached_gl.__file__).resolve().parents[2])
    if sdk_root not in sys.path:
        sys.path.insert(0, sdk_root)
    if "genlayer" not in sys.modules:
        importlib.invalidate_caches()
        importlib.import_module("genlayer")
    message = proxy.message
    sender = vm.sender
    if isinstance(sender, bytes):
        sender = type(message.sender_address)(sender)
    proxy._cached_gl.message = message._replace(
        sender_address=sender, origin_address=sender, value=type(message.value)(vm.value)
    )
    proxy._cached_gl.message_raw["sender_address"] = sender
    proxy._cached_gl.message_raw["origin_address"] = sender


def restore_validator_modules(contract):
    """Ensure validator subprocess/subcontext has access to genlayer SDK primitives."""
    proxy = contract._instance.register_release_audit.__globals__["gl"]
    if "genlayer" not in sys.modules:
        importlib.invalidate_caches()
        importlib.import_module("genlayer")
    module = sys.modules["genlayer"]
    module.gl = proxy._cached_gl
    sys.modules["genlayer.gl"] = proxy._cached_gl
    sys.modules["genlayer.gl.vm"] = proxy._cached_gl.vm


def cleanup_validator_modules():
    """Clean up monkeypatched validator modules."""
    sys.modules.pop("genlayer.gl.vm", None)
    sys.modules.pop("genlayer.gl", None)


def load_fixture_bytes():
    """Load canonical test fixtures."""
    sbom_bytes = (ROOT / "fixtures" / "sbom-complete.json").read_bytes()
    notice_bytes = (ROOT / "fixtures" / "notice-complete.md").read_bytes()
    return sbom_bytes, notice_bytes


def register_audit(vm, contract, commit=COMMIT_A, custom_notice_sha=None):
    """Helper to register an audit with canonical fixtures."""
    sbom_bytes, notice_bytes = load_fixture_bytes()
    sbom_sha = hashlib.sha256(sbom_bytes).hexdigest()
    notice_sha = custom_notice_sha or hashlib.sha256(notice_bytes).hexdigest()
    with vm.activate():
        sync_vm(vm, contract)
        return contract.register_release_audit(
            "Nidhogg Release v1.0.0",
            "9ja-maxx",
            "Nidhogg",
            commit,
            "fixtures/sbom-complete.json",
            "fixtures/notice-complete.md",
            sbom_sha,
            notice_sha,
            POLICY,
        )


def install_mocks(vm, token_line="COMPLIANT|COMPLIANT|COMPLIANT|COMPLIANT", candidate_notice=None):
    """Install mock web responses and mock LLM classification output."""
    sbom_bytes, notice_bytes = load_fixture_bytes()
    if candidate_notice is not None:
        notice_bytes = candidate_notice

    vm.clear_mocks()
    vm.mock_web(
        r"https://raw\.githubusercontent\.com/9ja-maxx/Nidhogg/.*fixtures/sbom-complete\.json",
        {"status": 200, "body": sbom_bytes},
    )
    vm.mock_web(
        r"https://raw\.githubusercontent\.com/9ja-maxx/Nidhogg/.*fixtures/notice-complete\.md",
        {"status": 200, "body": notice_bytes},
    )
    vm.mock_llm(r"(?s).*Return exactly one line containing pipe-delimited uppercase tokens.*", token_line)


def test_registration_validation_and_duplicate_rejection():
    """Test parameter sanitization, SSRF path prevention, and duplicate release prevention."""
    vm, contract, _, _ = deploy_nidhogg()
    sbom_bytes, notice_bytes = load_fixture_bytes()
    sd = hashlib.sha256(sbom_bytes).hexdigest()
    nd = hashlib.sha256(notice_bytes).hexdigest()

    with vm.activate():
        sync_vm(vm, contract)
        # Invalid organization slug
        assert contract.register_release_audit("L", "bad/owner", "repo", COMMIT_A, "a.json", "b.md", sd, nd, POLICY) == "INVALID_REPOSITORY"
        # Non-hex or non-40 commit
        assert contract.register_release_audit("L", "owner", "repo", "main", "a.json", "b.md", sd, nd, POLICY) == "INVALID_SOURCE_IDENTIFIERS"
        # Path traversal attempt
        assert contract.register_release_audit("L", "owner", "repo", COMMIT_A, "../a.json", "b.md", sd, nd, POLICY) == "INVALID_SOURCE_IDENTIFIERS"
        # Colliding paths
        assert contract.register_release_audit("L", "owner", "repo", COMMIT_A, "same.json", "same.json", sd, nd, POLICY) == "COLLIDING_ARTIFACT_PATHS"
        assert contract.get_total_audits() == "0"

    audit_id = register_audit(vm, contract)
    assert audit_id == 0

    record = json.loads(contract.get_audit_dossier(0))
    assert record["repository"] == "9ja-maxx/Nidhogg"
    assert record["commit"] == COMMIT_A
    assert record["status"] == "REGISTERED"

    # Duplicate release registration rejection
    with vm.activate():
        sync_vm(vm, contract)
        assert contract.register_release_audit(
            "Dup", "9ja-maxx", "Nidhogg", COMMIT_A, "fixtures/sbom-complete.json",
            "fixtures/notice-complete.md", sd, nd, POLICY
        ) == "DUPLICATE_RELEASE_REGISTRATION"
        assert contract.get_total_audits() == "1"


def test_happy_path_provenance_and_validator_reexecution():
    """Verify clean full evaluation, consensus re-execution, 100% compliance score, and replay block."""
    vm, contract, _, _ = deploy_nidhogg()
    audit_id = register_audit(vm, contract)
    install_mocks(vm, "COMPLIANT|COMPLIANT|COMPLIANT|COMPLIANT")

    with vm.activate():
        sync_vm(vm, contract)
        verdict = contract.execute_consensus_assessment(audit_id)
        assert verdict == "VERIFIED_COMPLIANT"

        dossier = json.loads(contract.get_audit_dossier(audit_id))
        assert dossier["status"] == "FINALIZED"
        assert dossier["compliance_score"] == 100

        obs = json.loads(dossier["observation"])
        assert obs["coverage"] == ["COMPLIANT", "COMPLIANT", "COMPLIANT", "COMPLIANT"]

        restore_validator_modules(contract)
        assert vm.run_validator() is True
        # Replay attempt fails
        assert contract.execute_consensus_assessment(audit_id) == "AUDIT_ALREADY_FINALIZED"
    cleanup_validator_modules()


def test_cryptographic_digest_tamper_detection():
    """Verify that tampering with either artifact digest causes immediate TAMPER_DETECTED."""
    vm, contract, _, _ = deploy_nidhogg()
    tampered_notice_sha = "0" * 64
    audit_id = register_audit(vm, contract, custom_notice_sha=tampered_notice_sha)
    install_mocks(vm)

    with vm.activate():
        sync_vm(vm, contract)
        verdict = contract.execute_consensus_assessment(audit_id)
        assert verdict == "TAMPER_DETECTED"

        dossier = json.loads(contract.get_audit_dossier(audit_id))
        obs = json.loads(dossier["observation"])
        assert obs["status"] == "DIGEST_MISMATCH"
        assert obs["packages"] == []


def test_permissive_gap_and_copyleft_conflict():
    """Verify license deficit and high-risk copyleft conflict derivations."""
    vm, contract, _, _ = deploy_nidhogg()
    audit_id = register_audit(vm, contract)
    install_mocks(vm, "COMPLIANT|PERMISSIVE_GAP|COMPLIANT|COMPLIANT")

    with vm.activate():
        sync_vm(vm, contract)
        assert contract.execute_consensus_assessment(audit_id) == "ATTRIBUTION_DEFICIT"

    # Copyleft conflict takes higher precedence
    vm2, contract2, _, _ = deploy_nidhogg()
    audit2 = register_audit(vm2, contract2)
    install_mocks(vm2, "COMPLIANT|PERMISSIVE_GAP|COPYLEFT_CONFLICT|COMPLIANT")

    with vm2.activate():
        sync_vm(vm2, contract2)
        assert contract2.execute_consensus_assessment(audit2) == "HIGH_RISK_LICENSE_VIOLATION"


def test_malformed_model_output_fails_closed():
    """Ensure malformed or unexpected model responses fail closed to INDETERMINATE."""
    for bad_output in (
        "COMPLIANT|COMPLIANT",  # count mismatch
        "Here is the result:\nCOMPLIANT|COMPLIANT|COMPLIANT|COMPLIANT",  # multi-line prose
        "COMPLIANT|COMPLIANT|UNKNOWN_TOKEN|COMPLIANT",  # invalid token
    ):
        vm, contract, _, _ = deploy_nidhogg()
        audit_id = register_audit(vm, contract)
        install_mocks(vm, bad_output)
        with vm.activate():
            sync_vm(vm, contract)
            assert contract.execute_consensus_assessment(audit_id) == "INDETERMINATE"


def test_validator_rejects_consequential_token_disagreement():
    """Verify that validator node rejects consensus if its classification differs from leader."""
    vm, contract, _, _ = deploy_nidhogg()
    audit_id = register_audit(vm, contract)
    install_mocks(vm, "COMPLIANT|COMPLIANT|COMPLIANT|COMPLIANT")

    with vm.activate():
        sync_vm(vm, contract)
        assert contract.execute_consensus_assessment(audit_id) == "VERIFIED_COMPLIANT"

    # Now validator observes a difference
    install_mocks(vm, "COMPLIANT|PERMISSIVE_GAP|COMPLIANT|COMPLIANT")
    with vm.activate():
        sync_vm(vm, contract)
        restore_validator_modules(contract)
        assert vm.run_validator() is False
    cleanup_validator_modules()


def test_immutable_remediation_linking():
    """Test creator-authenticated remediation linking between audits across different commits."""
    vm, contract, creator, outsider = deploy_nidhogg()
    first_audit = register_audit(vm, contract, COMMIT_A)
    second_audit = register_audit(vm, contract, COMMIT_B)

    for a in (first_audit, second_audit):
        install_mocks(vm)
        with vm.activate():
            sync_vm(vm, contract)
            assert contract.execute_consensus_assessment(a) == "VERIFIED_COMPLIANT"

    # Outsider attempt fails
    with vm.prank(outsider):
        sync_vm(vm, contract)
        assert contract.link_successor_remediation(first_audit, second_audit) == "UNAUTHORIZED_CREATOR_ONLY"

    # Creator links remediation
    with vm.activate():
        sync_vm(vm, contract)
        assert contract.link_successor_remediation(first_audit, second_audit) == "REMEDIATION_BOUND"
        # Duplicate link attempt fails
        assert contract.link_successor_remediation(first_audit, second_audit) == "REMEDIATION_ALREADY_BOUND"

        dossier = json.loads(contract.get_audit_dossier(first_audit))
        assert dossier["successor_plus_one"] == 2
