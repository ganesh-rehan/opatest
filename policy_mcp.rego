package authz_mcp

import future.keywords.if
import future.keywords.in

# ============================================================================
# CONFIGURATION
# ============================================================================

# Default allow (inverse logic - block specific tools)
default allow_decision := true

# Blocked MCP tools
blocked_tools := ["multiply", "divide"]

# Blocked MCP server names
blocked_server_names := ["shubh-calculator"]

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

# Get tool name from metadata
get_tool_name(metadata) := tool_name if {
    tool_name := metadata.tool_name
}

# Check if tool is blocked
is_tool_blocked(tool_name) if {
    tool_name in blocked_tools
}

# Check if server is blocked
is_server_blocked(server_name) if {
    server_name in blocked_server_names
}

# ============================================================================
# MCP TOOL VALIDATION RULES
# ============================================================================

# Rule 1: Block if tool is blocked
allow_decision := false if {
    tool_name := get_tool_name(input.metadata)
    is_tool_blocked(tool_name)
}

# Rule 2: Block if server is blocked
allow_decision := false if {
    is_server_blocked(input.metadata.mcp_server_name)
}


# ============================================================================
# VIOLATIONS & DESCRIPTIONS
# ============================================================================

# Success description
description := msg if {
    tool_name := get_tool_name(input.metadata)
    not is_tool_blocked(tool_name)
    not is_server_blocked(input.metadata.mcp_server_name)
    msg := sprintf("Tool validation successful: '%s' is allowed on server '%s'", [tool_name, input.metadata.mcp_server_name])
}

# Failure - tool blocked
description := msg if {
    tool_name := get_tool_name(input.metadata)
    is_tool_blocked(tool_name)
    msg := sprintf("Tool validation failed: '%s' is blocked. Blocked tools: [multiply, divide]", [tool_name])
}

# Failure - server blocked
description := msg if {
    tool_name := get_tool_name(input.metadata)
    not is_tool_blocked(tool_name)
    is_server_blocked(input.metadata.mcp_server_name)
    msg := sprintf("Tool validation failed: server '%s' is not allowed", [input.metadata.mcp_server_name])
}

# Default description if no tool_name
description := "Tool validation successful: No tool validation required" if {
    not input.metadata.tool_name
}

# ============================================================================
# VIOLATIONS
# ============================================================================

violations contains msg if {
    tool_name := get_tool_name(input.metadata)
    is_tool_blocked(tool_name)
    msg := sprintf("Tool '%s' is blocked. Blocked tools: [multiply, divide]", [tool_name])
}

violations contains msg if {
    is_server_blocked(input.metadata.mcp_server_name)
    msg := sprintf("Server '%s' is blocked", [input.metadata.mcp_server_name])
}

# ============================================================================
# RETURN FORMAT
# ============================================================================

# Return in format expected by handler
allow := {
    "allow": allow_decision,
    "description": description
}