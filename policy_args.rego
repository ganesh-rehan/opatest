package authz_args

import future.keywords.if
import future.keywords.in

# Default deny
default allow_decision := false

# Blocked URLs
blocked_urls := [
    "https://docs.litellm.ai/docs/proxy/guardrails/prompt_injection"
]

# Check if URL is blocked
is_url_blocked(url) if {
    url in blocked_urls
}

# Allow if tool arguments don't contain blocked URL
allow_decision if {
    # Get tool arguments
    args := input.request.arguments
    
    # Check if URL exists in arguments
    url := args.url
    
    # Allow if URL is not blocked
    not is_url_blocked(url)
}

# Allow if no URL in arguments
allow_decision if {
    args := input.request.arguments
    not args.url
}

# Return format
allow := {"allow": allow_decision}