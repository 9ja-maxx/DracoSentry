# v0.2.16
# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
"""
DracoVerifierHook — Downstream Gatekeeper & Compliance Oracle Hook
==================================================================
A lightweight smart contract that integrates with DracoSentry to provide
on-chain gating for decentralized package registries, automated release bounties,
and DAO software deployment pipelines.

Downstream protocols query this hook to assert that a given release commit
holds an immutable, unrevoked 'VERIFIED_COMPLIANT' certification.
"""

from genlayer import *
import json
import typing


class DracoVerifierHook(gl.Contract):
    sentry_registry: Address
    certified_releases: TreeMap[str, bool]

    def __init__(self, initial_sentry: Address):
        self.sentry_registry = initial_sentry

    @gl.public.view
    def is_release_certified(self, audit_id: u256) -> bool:
        """
        Query the configured DracoSentry contract to check if a release audit
        has achieved terminal VERIFIED_COMPLIANT status.
        """
        # Call DracoSentry.get_audit_dossier view method
        dossier_raw = gl.call(self.sentry_registry, "get_audit_dossier", [audit_id])
        if dossier_raw == "NOT_FOUND":
            return False
        
        try:
            dossier = json.loads(dossier_raw)
            return (
                dossier.get("status") == "FINALIZED"
                and dossier.get("verdict") == "VERIFIED_COMPLIANT"
                and dossier.get("compliance_score", 0) == 100
            )
        except Exception:
            return False

    @gl.public.write
    def record_certification(self, audit_id: u256) -> str:
        """
        Cache a verified release commit hash into the local fast-path registry.
        """
        dossier_raw = gl.call(self.sentry_registry, "get_audit_dossier", [audit_id])
        if dossier_raw == "NOT_FOUND":
            return "AUDIT_NOT_FOUND"

        try:
            dossier = json.loads(dossier_raw)
            if (
                dossier.get("status") == "FINALIZED"
                and dossier.get("verdict") == "VERIFIED_COMPLIANT"
            ):
                repo_commit = f"{dossier['repository']}@{dossier['commit']}"
                self.certified_releases[repo_commit] = True
                return "CERTIFIED_RECORDED"
            return "AUDIT_NOT_COMPLIANT"
        except Exception:
            return "PARSING_FAILED"
