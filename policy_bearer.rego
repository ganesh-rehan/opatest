package authz

# OPA guardrail with bearer auth: gateway calls POST /v1/data/authz/allow
# and expects response: { "result": { "allow": boolean } }.

# Default deny
default allow_decision := false

# --- LLM input: allow by identity ---
# Allow the service account from curl JWT (subjectSlug)
#allow_decision if {
#    input.metadata.subject == "default-cmk2c05v404d201tc7zt81q7f"
#}

# Allow by email when gateway sends user email as subject
#allow_decision if {
#    input.metadata.subject == "ganesh.balivada@truefoundry.com"
#}
allow_decision if {
    input.metadata.user_email == "ganesh.balivada@truefoundry.com"
}

# Path authz/allow returns this object so gateway gets result.allow
allow := {"allow": allow_decision}
