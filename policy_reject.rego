package authz

# Gateway calls POST /v1/data/authz/allow and expects response: { "result": { "allow": boolean } }.
# So data.authz.allow must be an object; we compute allow_decision then expose it as allow.

# Default deny
default allow_decision := false

# --- LLM input: allow by identity ---
# Allow the service account from your curl JWT (subjectSlug)
allow_decision if {
    input.metadata.subject == "default-cmk2c05v404d201tc7zt81q7f"
    input.metadata.subject == "test.balivada@truefoundry.com"
    input.metadata.user_email == "test.balivada@truefoundry.com"
}

# Allow by email when gateway sends user email as subject
#allow_decision if {
#    input.metadata.subject == "test.balivada@truefoundry.com"
#}
#allow_decision if {
#    input.metadata.user_email == "test.balivada@truefoundry.com"
#}

# Path authz/allow returns this object so gateway gets result.allow
allow := {"allow": allow_decision}