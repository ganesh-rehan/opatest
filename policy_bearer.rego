package authz_bearer

# OPA guardrail with bearer auth: gateway calls POST /v1/data/authz/allow
# and expects response: { "result": { "allow": boolean } }.

# Default deny
default allow_decision := false

allow_decision if {
    email := input.metadata.user_email
    endswith(email, "@truefoundry.com")
}

# Path authz/allow returns this object so gateway gets result.allow
allow := {"allow": allow_decision}
