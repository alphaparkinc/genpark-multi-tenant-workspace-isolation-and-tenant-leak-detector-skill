"""Example usage for Multi-Tenant Workspace Isolation & Tenant Leak Detector."""
from client import MultiTenantWorkspaceIsolationGuard

if __name__ == "__main__":
    res = MultiTenantWorkspaceIsolationGuard.audit_workspace_access(
        "tenant_99", "tenants/tenant_99/config.json", "tenant_99"
    )
    print("Access Allowed:", res["access_allowed"], "Alerts:", res["security_alerts"])
