package authz_fetch

# Default deny
default allow_decision := false

# Block fetch tool from nm fetch mcp server
allow_decision if {
    not is_blocked_tool
}

is_blocked_tool if {
    input.metadata.tool_name == "fetch"
    input.metadata.mcp_server_name == "nm fetch"
}

# Return format expected by handler
allow := {"allow": allow_decision}