# Piece 1: Kubernetes Read-Only MCP Server

This directory contains the deployment manifests for the Kubernetes read-only MCP server.

## What This Does

Deploys an MCP server that provides read-only introspection tools for Kubernetes resources:
- List and describe pods
- Get pod logs
- List events
- List deployments and services

The server is scoped to specific namespaces via RBAC: `agent-team` and `kagenti-system`.

## Files

- `rbac.yaml` - ServiceAccount and RBAC permissions (read-only)
- `component.yaml` - Kagenti Component CR that deploys the server

## Prerequisites

- Kagenti operator installed
- `agent-team` namespace created
- `kagenti-system` namespace exists

## Deployment

```bash
# Create namespace if needed
kubectl create namespace agent-team

# Apply RBAC first
kubectl apply -f rbac.yaml

# Deploy the MCP server via Component CR
kubectl apply -f component.yaml

# Verify deployment
kubectl get component k8s-readonly-server -n agent-team
kubectl get pods -n agent-team -l app=k8s-readonly-server
```

## Testing

Once deployed, the MCP server will be available at:
- Service: `k8s-readonly-server.agent-team.svc.cluster.local:8080`
- Health check: `http://k8s-readonly-server.agent-team.svc.cluster.local:8080/health`

You can test the tools using an MCP client or through the MCP Gateway (configured in the next piece).

## Next Steps

Piece 2 will configure the MCP Gateway to expose this server with the `k8s_` tool prefix.
