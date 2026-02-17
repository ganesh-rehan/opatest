package authz_team_deny

# Gateway calls POST /v1/data/authz_team/allow and expects response: { "result": { "allow": boolean } }.
# So data.authz_team.allow must be an object; we compute allow_decision then expose it as allow.

# Default deny
default allow_decision := false

allow_decision if {
    input.metadata.team_name == "other-team"
}

# Path authz_team/allow returns this object so gateway gets result.allow
allow := {"allow": allow_decision}