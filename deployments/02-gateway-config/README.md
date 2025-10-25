# Piece 2: MCP Gateway Configuration

This directory contains the configuration to expose the k8s-readonly-server via MCP Gateway.

## What This Does

Configures the MCP Gateway to aggregate tools from the k8s-readonly-server:
- Tools are prefixed with `k8s_` to avoid naming conflicts
- Gateway routes requests to the backend server
- Agents can discover and use these tools through the gateway

## Resources

**HTTPRoute** (`k8s-readonly-server-route`):
- References the `mcp-gateway` in `gateway-system`
- Hostname: `k8s-readonly.agent-team.svc.cluster.local`
- Path prefix: `/k8s-readonly`
- Backend: `k8s-readonly-server` service on port 8080

**MCPServer** (`k8s-readonly-server`):
- References the HTTPRoute
- Tool prefix: `k8s_`
- MCP Gateway controller discovers this and aggregates tools

## Tools Available

Once exposed via the gateway, the following tools are available with the `k8s_` prefix:
- `k8s_get_pods` - List pods in a namespace
- `k8s_get_pod_logs` - Get logs from a pod
- `k8s_get_events` - List events in a namespace
- `k8s_get_deployments` - List deployments
- `k8s_get_services` - List services
- `k8s_describe_pod` - Get detailed pod information

## Deployment

```bash
# Apply the gateway configuration
oc apply -f k8s-readonly-route.yaml

# Verify MCPServer is ready
oc get mcpserver k8s-readonly-server -n agent-team

# Should show:
# NAME                  READY   TARGETS   PREFIX   AGE
# k8s-readonly-server   True              k8s_     ...
```

## Next Steps

Agents can now access these tools by connecting to the MCP Gateway endpoint.
