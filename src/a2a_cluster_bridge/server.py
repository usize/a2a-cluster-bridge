#!/usr/bin/env python3
"""
MCP Server for A2A Agent Discovery using Kagenti's AgentCard CRD.

This server provides tools to discover and interact with A2A-compliant agents
in Kubernetes clusters running Kagenti. It uses the AgentCard CRD which caches
agent card data, eliminating the need for direct HTTP calls to agent endpoints.
"""

import subprocess
import json
import httpx
from typing import Optional, Dict, Any, List
from uuid import uuid4
from fastmcp import FastMCP

from a2a.client import A2ACardResolver, A2AClient
from a2a.types import (
    AgentCard,
    MessageSendParams,
    SendMessageRequest,
    SendStreamingMessageRequest,
)
from a2a.utils.constants import EXTENDED_AGENT_CARD_PATH


# Create the MCP server
mcp = FastMCP("A2A Cluster Bridge")


def check_kubectl_access() -> bool:
    """Check if user has kubectl access to the cluster."""
    try:
        result = subprocess.run(
            ["kubectl", "auth", "can-i", "get", "agentcards"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.returncode == 0 and "yes" in result.stdout.lower()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def get_namespace_scope(
    namespace: Optional[str] = None, all_namespaces: bool = False
) -> tuple[str, str]:
    """Determine namespace scope for kubectl commands."""
    if all_namespaces:
        return "--all-namespaces", "all namespaces"
    elif namespace:
        return f"-n {namespace}", f"namespace: {namespace}"
    else:
        # Get current namespace from context
        try:
            result = subprocess.run(
                ["kubectl", "config", "view", "--minify", "-o", "jsonpath={..namespace}"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0 and result.stdout.strip():
                current_ns = result.stdout.strip()
                return f"-n {current_ns}", f"current namespace: {current_ns}"
            else:
                # Default to 'default' namespace if none set
                return "-n default", "namespace: default"
        except subprocess.TimeoutExpired:
            raise Exception("Timeout checking current namespace")


def discover_agent_cards(namespace_flag: str) -> List[Dict[str, Any]]:
    """Discover AgentCard resources using kubectl."""
    try:
        # Run kubectl command to get AgentCard CRs
        cmd = f"kubectl get agentcards {namespace_flag} -o json"
        result = subprocess.run(
            cmd.split(), capture_output=True, text=True, timeout=30
        )

        if result.returncode != 0:
            raise Exception(f"kubectl command failed: {result.stderr}")

        agent_cards_data = json.loads(result.stdout)
        return agent_cards_data.get("items", [])

    except subprocess.TimeoutExpired:
        raise Exception("Timeout discovering agent cards")
    except json.JSONDecodeError as e:
        raise Exception(f"Failed to parse kubectl response: {e}")


@mcp.tool()
def discover_agents(
    namespace: Optional[str] = None,
    all_namespaces: bool = False,
) -> str:
    """
    Discover agents in the Kubernetes cluster using AgentCard resources.

    AgentCards cache agent card data, so this tool returns immediately without
    making HTTP calls to agent endpoints. The Kagenti operator keeps this data
    up-to-date automatically.

    Args:
        namespace: Specific namespace to search (optional)
        all_namespaces: Search across all namespaces (default: False)

    Returns:
        JSON array of discovered agents with their cached metadata
    """

    # Check kubectl access
    if not check_kubectl_access():
        raise Exception(
            "No access to AgentCard resources. "
            "Ensure you are logged into the Kubernetes cluster and have "
            "permissions to get AgentCard resources."
        )

    # Get namespace scope
    namespace_flag, scope_msg = get_namespace_scope(namespace, all_namespaces)

    # Discover AgentCard CRs
    agent_card_crs = discover_agent_cards(namespace_flag)

    if not agent_card_crs:
        return (
            f"No agents found in {scope_msg}.\n\n"
            "AgentCards are automatically created by the Kagenti operator when "
            "Agents are deployed with the kagenti.io/type=agent label."
        )

    # Process discovered AgentCard CRs
    agents = []
    for card_cr in agent_card_crs:
        metadata = card_cr.get("metadata", {})
        spec = card_cr.get("spec", {})
        status = card_cr.get("status", {})

        # Extract basic metadata
        card_name = metadata.get("name", "unknown")
        card_namespace = metadata.get("namespace", "")

        # Get cached agent card data from status
        card_data = status.get("card", {})

        # Get sync status
        conditions = status.get("conditions", [])
        synced_condition = next(
            (c for c in conditions if c.get("type") == "Synced"), {}
        )
        sync_status = synced_condition.get("status", "Unknown")
        sync_message = synced_condition.get("message", "")

        last_sync_time = status.get("lastSyncTime", "")
        protocol = status.get("protocol", "unknown")

        agent_info = {
            "agentcard_name": card_name,
            "namespace": card_namespace,
            "agent_name": card_data.get("name", ""),
            "description": card_data.get("description", ""),
            "version": card_data.get("version", ""),
            "url": card_data.get("url", ""),
            "protocol": protocol,
            "capabilities": card_data.get("capabilities", {}),
            "skills": card_data.get("skills", []),
            "supports_authenticated_extended_card": card_data.get(
                "supportsAuthenticatedExtendedCard", False
            ),
            "sync_status": sync_status,
            "sync_message": sync_message,
            "last_sync_time": last_sync_time,
        }

        agents.append(agent_info)

    result_text = f"Found {len(agents)} agent(s) in {scope_msg}:\n\n"
    result_text += json.dumps(agents, indent=2)

    return result_text


@mcp.tool()
def list_agents(namespace: Optional[str] = None, all_namespaces: bool = False) -> str:
    """
    Get a summary table of all discovered agents.

    Returns a formatted table showing key information about each agent,
    including name, version, protocol, sync status, and URL.

    Args:
        namespace: Specific namespace to search (optional)
        all_namespaces: Search across all namespaces (default: False)

    Returns:
        Formatted table of agent information
    """

    # Get agent data using discover_agents
    try:
        agents_json = discover_agents(namespace, all_namespaces)

        # Check if it's an error message
        if "No agents found" in agents_json or "Error:" in agents_json:
            return agents_json

        # Parse the JSON from the discover result
        lines = agents_json.split("\n")
        json_start = next(
            i for i, line in enumerate(lines) if line.strip().startswith("[")
        )
        json_content = "\n".join(lines[json_start:])
        agents = json.loads(json_content)

        # Create summary table
        summary = "Agent Summary:\n\n"
        summary += f"{'AGENT NAME':<25} {'VERSION':<12} {'PROTOCOL':<10} {'SYNCED':<8} {'NAMESPACE':<20} {'URL':<50}\n"
        summary += f"{'-'*25} {'-'*12} {'-'*10} {'-'*8} {'-'*20} {'-'*50}\n"

        for agent in agents:
            agent_name = agent["agent_name"] or agent["agentcard_name"]
            version = agent["version"] or "N/A"
            protocol = agent["protocol"]
            synced = "Yes" if agent["sync_status"] == "True" else "No"
            namespace = agent["namespace"]
            url = agent["url"] or "N/A"

            summary += f"{agent_name:<25} {version:<12} {protocol:<10} {synced:<8} {namespace:<20} {url:<50}\n"

        summary += f"\nTotal: {len(agents)} agent(s)"

        return summary

    except Exception as e:
        raise Exception(f"Error creating agent summary: {e}")


@mcp.tool()
def get_agent_details(agentcard_name: str, namespace: str) -> str:
    """
    Get detailed information about a specific agent including all skills.

    Args:
        agentcard_name: Name of the AgentCard resource
        namespace: Namespace where the AgentCard exists

    Returns:
        Detailed JSON information about the agent and its capabilities
    """

    try:
        # Get the specific AgentCard
        cmd = f"kubectl get agentcard {agentcard_name} -n {namespace} -o json"
        result = subprocess.run(
            cmd.split(), capture_output=True, text=True, timeout=10
        )

        if result.returncode != 0:
            raise Exception(
                f"Failed to get AgentCard '{agentcard_name}' in namespace '{namespace}': {result.stderr}"
            )

        card_cr = json.loads(result.stdout)
        card_data = card_cr.get("status", {}).get("card", {})

        if not card_data:
            raise Exception(
                f"AgentCard '{agentcard_name}' has no cached card data. "
                "The agent may not be ready or the sync may have failed."
            )

        result_text = f"Agent details for {agentcard_name}:\n\n"
        result_text += json.dumps(card_data, indent=2)

        return result_text

    except subprocess.TimeoutExpired:
        raise Exception("Timeout getting AgentCard details")
    except json.JSONDecodeError as e:
        raise Exception(f"Failed to parse AgentCard data: {e}")


@mcp.tool()
async def send_message_to_agent(
    agent_url: str,
    message: str,
    auth_token: Optional[str] = None,
    use_extended_card: bool = False,
) -> str:
    """
    Send a message to an A2A agent and get the response.

    Args:
        agent_url: The base URL of the agent (from AgentCard status.card.url)
        message: The message text to send
        auth_token: Optional OAuth token for authenticated requests
        use_extended_card: Whether to attempt fetching the extended agent card

    Returns:
        JSON response from the agent
    """

    async with httpx.AsyncClient(verify=False, timeout=30) as httpx_client:
        # Initialize A2ACardResolver
        resolver = A2ACardResolver(
            httpx_client=httpx_client,
            base_url=agent_url,
        )

        # Fetch agent card
        final_agent_card_to_use: AgentCard | None = None

        try:
            # Try to get the public agent card first
            public_card = await resolver.get_agent_card()
            final_agent_card_to_use = public_card

            # If auth token provided and extended card requested, try to get it
            if (
                auth_token
                and use_extended_card
                and public_card.supports_authenticated_extended_card
            ):
                try:
                    auth_headers_dict = {"Authorization": f"Bearer {auth_token}"}
                    extended_card = await resolver.get_agent_card(
                        relative_card_path=EXTENDED_AGENT_CARD_PATH,
                        http_kwargs={"headers": auth_headers_dict},
                    )
                    final_agent_card_to_use = extended_card
                except Exception:
                    # Fall back to public card if extended card fails
                    pass

        except Exception as e:
            raise Exception(f"Failed to fetch agent card from {agent_url}: {e}")

        # Initialize client and send message
        client = A2AClient(
            httpx_client=httpx_client, agent_card=final_agent_card_to_use
        )

        send_message_payload = {
            "message": {
                "role": "user",
                "parts": [{"kind": "text", "text": message}],
                "messageId": uuid4().hex,
            },
        }

        request = SendMessageRequest(
            id=str(uuid4()), params=MessageSendParams(**send_message_payload)
        )

        try:
            response = await client.send_message(request)
            return f"Response from {agent_url}:\n\n{response.model_dump_json(indent=2, exclude_none=True)}"
        except Exception as e:
            raise Exception(f"Failed to send message to agent: {e}")


@mcp.tool()
async def send_streaming_message_to_agent(
    agent_url: str,
    message: str,
    auth_token: Optional[str] = None,
    use_extended_card: bool = False,
) -> str:
    """
    Send a streaming message to an A2A agent and get the streaming response.

    Args:
        agent_url: The base URL of the agent (from AgentCard status.card.url)
        message: The message text to send
        auth_token: Optional OAuth token for authenticated requests
        use_extended_card: Whether to attempt fetching the extended agent card

    Returns:
        All streaming response chunks from the agent as JSON
    """

    async with httpx.AsyncClient(verify=False, timeout=30) as httpx_client:
        # Initialize A2ACardResolver
        resolver = A2ACardResolver(
            httpx_client=httpx_client,
            base_url=agent_url,
        )

        # Fetch agent card
        final_agent_card_to_use: AgentCard | None = None

        try:
            # Try to get the public agent card first
            public_card = await resolver.get_agent_card()
            final_agent_card_to_use = public_card

            # If auth token provided and extended card requested, try to get it
            if (
                auth_token
                and use_extended_card
                and public_card.supports_authenticated_extended_card
            ):
                try:
                    auth_headers_dict = {"Authorization": f"Bearer {auth_token}"}
                    extended_card = await resolver.get_agent_card(
                        relative_card_path=EXTENDED_AGENT_CARD_PATH,
                        http_kwargs={"headers": auth_headers_dict},
                    )
                    final_agent_card_to_use = extended_card
                except Exception:
                    # Fall back to public card if extended card fails
                    pass

        except Exception as e:
            raise Exception(f"Failed to fetch agent card from {agent_url}: {e}")

        # Initialize client and send streaming message
        client = A2AClient(
            httpx_client=httpx_client, agent_card=final_agent_card_to_use
        )

        send_message_payload = {
            "message": {
                "role": "user",
                "parts": [{"kind": "text", "text": message}],
                "messageId": uuid4().hex,
            },
        }

        streaming_request = SendStreamingMessageRequest(
            id=str(uuid4()), params=MessageSendParams(**send_message_payload)
        )

        try:
            stream_response = client.send_message_streaming(streaming_request)

            result_chunks = []
            async for chunk in stream_response:
                result_chunks.append(chunk.model_dump(mode="json", exclude_none=True))

            return f"Streaming response from {agent_url}:\n\n" + "\n\n".join(
                [json.dumps(chunk, indent=2) for chunk in result_chunks]
            )

        except Exception as e:
            raise Exception(f"Failed to send streaming message to agent: {e}")


def main():
    """Run the MCP server."""
    mcp.run()


if __name__ == "__main__":
    main()
