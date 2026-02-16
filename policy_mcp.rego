package authz

import future.keywords.if
import future.keywords.in

# ============================================================================
# CONFIGURATION
# ============================================================================

# Default deny
default allow_decision := false

# Allowed MCP tools
allowed_tools := ["add", "subtract"]

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

# Get tool name from metadata
get_tool_name(metadata) := tool_name if {
    tool_name := metadata.tool_name
}

# Check if tool is allowed
is_tool_allowed(tool_name) if {
    tool_name in allowed_tools
}

# ============================================================================
# MCP TOOL VALIDATION RULES
# ============================================================================

# Rule: Allow only specific MCP tools (add and subtract)
allow_decision if {
    # Check if this is an MCP tool call (has tool_name in metadata)
    tool_name := get_tool_name(input.metadata)
    
    # Check if tool is in allowed list
    is_tool_allowed(tool_name)
}

# ============================================================================
# VIOLATIONS & DESCRIPTIONS
# ============================================================================

# Success description
description := msg if {
    tool_name := get_tool_name(input.metadata)
    is_tool_allowed(tool_name)
    msg := sprintf("Tool validation successful: '%s' is allowed", [tool_name])
}

# Failure description
description := msg if {
    tool_name := get_tool_name(input.metadata)
    not is_tool_allowed(tool_name)
    msg := sprintf("Tool validation failed: '%s' is not in allowed list [add, subtract]", [tool_name])
}

# Default description if no tool_name
description := "Tool validation failed: No tool name provided" if {
    not input.metadata.tool_name
}

# Violations for debugging
violations contains msg if {
    tool_name := get_tool_name(input.metadata)
    not is_tool_allowed(tool_name)
    msg := sprintf("Tool '%s' is not allowed. Allowed tools: [add, subtract]", [tool_name])
}

violations contains "No tool name provided in metadata" if {
    not input.metadata.tool_name
}

# ============================================================================
# RETURN FORMAT
# ============================================================================

# Return in format expected by handler
allow := {
    "allow": allow_decision,
    "description": description
}
