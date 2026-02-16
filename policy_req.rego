package authz

import future.keywords.if
import future.keywords.in

# ============================================================================
# CONFIGURATION
# ============================================================================

# Default deny
default allow_decision := false

# Allowed models
allowed_models := [
    "vertex-main/gemini-2-5-flash",
    "vertex-main/gemini-1.5-pro",
    "openai/gpt-3.5-turbo",
    "openai/gpt-4o-mini",
    "anthropic/claude-3-haiku"
]

# Blocked models
blocked_models := [
    "openai/gpt-4",
    "anthropic/claude-3-opus"
]

# Blocked keywords in messages
blocked_keywords := [
    "hack",
    "exploit",
    "jailbreak",
    "ignore previous",
    "disregard instructions",
    "bypass security",
    "override system",
    "sudo mode",
    "admin access"
]

# Harmful patterns
harmful_patterns := [
    "how to make a bomb",
    "how to hack",
    "illegal drugs",
    "how to steal",
    "violent attack"
]

# Maximum total message length (characters)
max_total_message_length := 500000

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

# Extract all user messages
get_user_messages(messages) := user_msgs if {
    user_msgs := [msg | 
        msg := messages[_]
        msg.role == "user"
    ]
}

# Check if text contains blocked keywords
contains_blocked_keywords(text) if {
    lower_text := lower(text)
    keyword := blocked_keywords[_]
    contains(lower_text, keyword)
}

# Check if text contains harmful patterns
contains_harmful_patterns(text) if {
    lower_text := lower(text)
    pattern := harmful_patterns[_]
    contains(lower_text, pattern)
}

# Count total characters in all messages
total_message_length(messages) := total if {
    lengths := [count(msg.content) | msg := messages[_]]
    total := sum(lengths)
}

# Check if any user message has blocked content
has_blocked_content(messages) if {
    user_msgs := get_user_messages(messages)
    msg := user_msgs[_]
    contains_blocked_keywords(msg.content)
}

# Check if any user message has harmful content
has_harmful_content(messages) if {
    user_msgs := get_user_messages(messages)
    msg := user_msgs[_]
    contains_harmful_patterns(msg.content)
}

# ============================================================================
# VALIDATION RULES
# ============================================================================

# Rule 1: Allow if model is in allowed list AND messages are clean
allow_decision if {
    # not input.response  # Input validation only
    
    # Check model
    model := input.request.model
    model in allowed_models
    
    # Check model is not blocked
    not model in blocked_models
    
    # Check messages exist
    messages := input.request.messages
    count(messages) > 0
    
    # Must have at least one user message
    user_msgs := get_user_messages(messages)
    count(user_msgs) > 0
    
    # Check no blocked keywords
    not has_blocked_content(messages)
    
    # Check no harmful patterns
    not has_harmful_content(messages)
    
    # Check message length
    total_message_length(messages) <= max_total_message_length
}

# ============================================================================
# VIOLATIONS (for debugging)
# ============================================================================

violations contains msg if {
    not input.response
    model := input.request.model
    not model in allowed_models
    msg := sprintf("Model '%s' is not in allowed list", [model])
}

violations contains msg if {
    not input.response
    model := input.request.model
    model in blocked_models
    msg := sprintf("Model '%s' is blocked", [model])
}

violations contains msg if {
    not input.response
    messages := input.request.messages
    has_blocked_content(messages)
    msg := "Message contains blocked keywords"
}

violations contains msg if {
    not input.response
    messages := input.request.messages
    has_harmful_content(messages)
    msg := "Message contains harmful patterns"
}

violations contains msg if {
    not input.response
    messages := input.request.messages
    total := total_message_length(messages)
    total > max_total_message_length
    msg := sprintf("Total message length (%d) exceeds limit (%d)", [total, max_total_message_length])
}

violations contains msg if {
    not input.response
    messages := input.request.messages
    user_msgs := get_user_messages(messages)
    count(user_msgs) == 0
    msg := "No user messages found in request"
}

# ============================================================================
# RETURN FORMAT FOR HANDLER
# ============================================================================

# Return in format expected by OPA handler: {"allow": boolean}
allow := {"allow": allow_decision}
