package authz_model_access

import future.keywords.if
import future.keywords.in

# Default deny
default allow_decision := false

# Sensitive models that require trusted domain
sensitive_models := [
    "openai-main/gpt-4",
    "vertex-main/gemini-2-5-flash"
]

# Trusted email domain
trusted_domain := "@truefoundry.com"

# Check if model is sensitive
is_sensitive_model(model) if {
    model in sensitive_models
}

# Allow if model is NOT sensitive (always allowed)
allow_decision if {
    model := input.request.model
    not is_sensitive_model(model)
}

# Allow if model is sensitive AND user has trusted email domain
allow_decision if {
    model := input.request.model
    is_sensitive_model(model)
    
    email := input.metadata.user_email
    endswith(email, trusted_domain)
}

# Descriptions
description := "Request allowed" if {
    model := input.request.model
    not is_sensitive_model(model)
}

description := "Request allowed" if {
    model := input.request.model
    is_sensitive_model(model)
    
    email := input.metadata.user_email
    endswith(email, trusted_domain)
}

description := "Request blocked: your email domain is not allowed to access the requested LLM model" if {
    model := input.request.model
    is_sensitive_model(model)
    
    email := input.metadata.user_email
    not endswith(email, trusted_domain)
}

# Return format
allow := {
    "allow": allow_decision,
    "desc": description
}