"""MCP server for Multi-Tenant Workspace Isolation & Tenant Leak Detector."""
import sys
import json
from client import MultiTenantWorkspaceIsolationGuard

def handle_request(req):
    method = req.get("method")
    if method == "tools/list":
        return {
            "tools": [{
                "name": "audit_workspace_access",
                "description": "Audits file access to ensure strict tenant isolation and block path traversals",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "tenant_id": {"type": "string"},
                        "file_path": {"type": "string"},
                        "session_tenant": {"type": "string"}
                    },
                    "required": ["tenant_id", "file_path", "session_tenant"]
                }
            }]
        }
    elif method == "tools/call":
        params = req.get("params", {})
        if params.get("name") == "audit_workspace_access":
            args = params.get("arguments", {})
            res = MultiTenantWorkspaceIsolationGuard.audit_workspace_access(
                args.get("tenant_id", ""),
                args.get("file_path", ""),
                args.get("session_tenant", "")
            )
            return {"content": [{"type": "text", "text": json.dumps(res, indent=2)}]}
    return {"error": "Method not found"}

if __name__ == "__main__":
    for line in sys.stdin:
        if line.strip():
            print(json.dumps(handle_request(json.loads(line))))
            sys.stdout.flush()
