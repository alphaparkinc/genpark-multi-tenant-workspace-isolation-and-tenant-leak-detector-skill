"""Multi-Tenant Workspace Isolation & Tenant Leak Detector.
100% Python Standard Library.
"""

class MultiTenantWorkspaceIsolationGuard:
    """Detects path traversal breakouts, tenant context mixing, and unauthorized cross-tenant object access."""

    @staticmethod
    def audit_workspace_access(tenant_id: str, file_path: str, session_tenant: str) -> dict:
        is_isolated = True
        reasons = []

        if tenant_id != session_tenant:
            is_isolated = False
            reasons.append(f"Cross-tenant context violation: token belongs to '{session_tenant}', tried accessing '{tenant_id}'")

        clean_path = file_path.replace("\\", "/")
        if "../" in clean_path or "/.." in clean_path or clean_path.startswith("/"):
            is_isolated = False
            reasons.append("Path traversal attempt detected outside workspace boundary")

        expected_prefix = f"tenants/{tenant_id}/"
        if not clean_path.startswith(expected_prefix):
            is_isolated = False
            reasons.append(f"File path must strictly reside within '{expected_prefix}'")

        return {
            "tenant_id": tenant_id,
            "access_allowed": is_isolated,
            "security_alerts": reasons
        }
