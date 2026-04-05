package authz_fetch

# Default deny
default allow_decision := false
default description := "Request denied by default policy"

# Block fetch tool from nm fetch mcp server
allow_decision if {
    not is_blocked_tool
}

is_blocked_tool if {
    input.metadata.tool_name == "fetch"
    input.metadata.mcp_server_name == "nm-fetch"
}

# Set description based on decision
description := "Tool 'fetch' from MCP server 'nm-fetch' is blocked" if {
    is_blocked_tool
}

description := "Request allowed" if {
    allow_decision
}

# Return format expected by handler
allow := {
    "allow": allow_decision,
    "desc": description
}