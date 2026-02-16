package authz

# Gateway calls POST /v1/data/authz/allow and expects response: { "result": { "allow": boolean } }.
# Policy path remains authz/allow. Allow when X-User-Email header value is test@example.com.
# Pass the header via x-tfy-metadata, e.g.: -H "x-tfy-metadata: {\"X-User-Email\": \"test@example.com\"}"

default allow_decision := false

allow_decision if {
    input.metadata["X-User-Email"] == "test@example.com"
}

# Normalized header key (some runtimes send lowercase)
allow_decision if {
    input.metadata["x-user-email"] == "test@example.com"
}

allow := {"allow": allow_decision}
