# A2A Cluster Bridge

## About

The cluster bridge is an MCP server which leverages kagenti's inbuilt discovery via `AgentCard` resources to dynamically find and invoke agents
running within a given kubernetes namespace.

A team of agents is provided, where one, a 'group leader', has access to the bridge and uses it to coordinate efforts among a group of specialist agents.
