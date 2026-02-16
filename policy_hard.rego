package authz

import future.keywords.if
import future.keywords.in

# ============================================================================
# CONFIGURATION & DEFAULTS
# ============================================================================

# Default deny - fail secure
default allow := false

# Role hierarchy (higher number = more permissions)
role_hierarchy := {
    "admin": 100,
    "manager": 75,
    "developer": 50,
    "analyst": 40,
    "viewer": 10,
    "guest": 0
}

# Sensitive keywords for content filtering
sensitive_keywords := [
    "password", "secret", "api_key", "credit_card", 
    "ssn", "social_security", "confidential", "private_key",
    "bearer_token", "access_token", "aws_secret"
]

# Toxic/harmful content patterns
toxic_patterns := [
    "hate", "kill", "attack", "violent", "bomb",
    "racist", "terrorism", "illegal", "weapon"
]

# Allowed domains for email addresses
allowed_email_domains := [
    "truefoundry.com",
    "example.com",
    "test.com"
]

# Business hours (UTC)
business_hours_start := 9
business_hours_end := 18

# Maximum token limits by role
max_tokens_by_role := {
    "admin": 10000,
    "manager": 5000,
    "developer": 3000,
    "analyst": 2000,
    "viewer": 1000,
    "guest": 500
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

# Get user role from metadata
get_user_role(metadata) := role if {
    role := metadata.user_role
} else := "guest"

# Get role level
get_role_level(role) := level if {
    level := role_hierarchy[role]
} else := 0

# Check if user has minimum role level
has_min_role(metadata, required_role) if {
    user_role := get_user_role(metadata)
    user_level := get_role_level(user_role)
    required_level := get_role_level(required_role)
    user_level >= required_level
}

# Extract email domain
get_email_domain(email) := domain if {
    parts := split(email, "@")
    count(parts) == 2
    domain := parts[1]
}

# Check if current time is within business hours
is_business_hours if {
    # Get current hour (would need to be passed in metadata in real scenario)
    current_hour := to_number(input.metadata.current_hour)
    current_hour >= business_hours_start
    current_hour < business_hours_end
}

# Check if text contains any sensitive keywords
contains_sensitive_content(text) if {
    lower_text := lower(text)
    keyword := sensitive_keywords[_]
    contains(lower_text, keyword)
}

# Check if text contains toxic content
contains_toxic_content(text) if {
    lower_text := lower(text)
    pattern := toxic_patterns[_]
    contains(lower_text, pattern)
}

# Count tokens (simple word count approximation)
count_tokens(text) := token_count if {
    words := split(text, " ")
    token_count := count(words)
}

# Check if user is from allowed tenant
is_allowed_tenant(tenant_name) if {
    allowed_tenants := ["truefoundry", "acme-corp", "test-org"]
    tenant_name in allowed_tenants
}

# ============================================================================
# INPUT GUARDRAIL RULES (LLM Input & MCP Tool Calls)
# ============================================================================

# Rule 1: Authentication - Service Account
allow if {
    not input.response  # Only for input guardrails
    input.metadata.subject == "default-cmk2c05v404d201tc7zt81q7f"
}

# Rule 2: Authentication - Email with domain check
allow if {
    not input.response
    email := input.metadata.user_email
    domain := get_email_domain(email)
    domain in allowed_email_domains
}

# Rule 3: Authentication - Admin users always allowed
allow if {
    not input.response
    has_min_role(input.metadata, "admin")
}

# Rule 4: Role-based access - Managers can access during business hours
allow if {
    not input.response
    has_min_role(input.metadata, "manager")
    is_business_hours
}

# Rule 5: Team-based access - Engineering team
allow if {
    not input.response
    input.metadata.team_name == "engineering"
    has_min_role(input.metadata, "developer")
}

# Rule 6: Tenant-based access
allow if {
    not input.response
    is_allowed_tenant(input.metadata.tenant_name)
    has_min_role(input.metadata, "viewer")
}

# Rule 7: Token limit check for input
allow if {
    not input.response
    user_role := get_user_role(input.metadata)
    max_tokens := max_tokens_by_role[user_role]
    
    # Check if request has max_tokens specified
    request_tokens := input.request.max_tokens
    request_tokens <= max_tokens
}

# Rule 8: Model access control
allow if {
    not input.response
    has_min_role(input.metadata, "developer")
    
    # Only certain roles can use expensive models
    model := input.request.model
    not contains(model, "gpt-4")  # GPT-4 requires admin
}

# Rule 9: Prevent prompt injection attempts
allow if {
    not input.response
    
    # Check user message doesn't contain injection patterns
    messages := input.request.messages
    message := messages[_]
    message.role == "user"
    
    injection_patterns := ["ignore previous", "system:", "you are now", "disregard"]
    lower_content := lower(message.content)
    
    # None of the patterns should be in the message
    not contains_injection_pattern(lower_content, injection_patterns)
}

contains_injection_pattern(text, patterns) if {
    pattern := patterns[_]
    contains(text, pattern)
}

# Rule 10: MCP tool access control
allow if {
    not input.response
    input.metadata.tool_name  # This is an MCP tool call
    
    # Developers and above can use calculator
    tool := input.metadata.tool_name
    tool == "calculator"
    has_min_role(input.metadata, "developer")
}

# ============================================================================
# OUTPUT GUARDRAIL RULES (LLM Output & MCP Tool Results)
# ============================================================================

# Rule 11: Allow safe output content
allow if {
    input.response  # Only for output guardrails
    response_text := input.response.json.choices[0].message.content
    
    # Must not contain sensitive keywords
    not contains_sensitive_content(response_text)
    
    # Must not contain toxic content
    not contains_toxic_content(response_text)
}

# Rule 12: Length-based output filtering
allow if {
    input.response
    response_text := input.response.json.choices[0].message.content
    
    # Response must not be too long (prevents data exfiltration)
    token_count := count_tokens(response_text)
    token_count <= 2000
    
    # Content is safe
    not contains_sensitive_content(response_text)
}

# Rule 13: Email pattern detection in output
allow if {
    input.response
    response_text := input.response.json.choices[0].message.content
    
    # Check for email patterns
    not contains_email_pattern(response_text)
    not contains_sensitive_content(response_text)
}

contains_email_pattern(text) if {
    # Simple email regex pattern check
    regex.match(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`, text)
}

# Rule 14: Phone number detection in output
allow if {
    input.response
    response_text := input.response.json.choices[0].message.content
    
    # Check for phone number patterns
    not contains_phone_pattern(response_text)
}

contains_phone_pattern(text) if {
    # US phone number patterns
    regex.match(`\d{3}[-.]?\d{3}[-.]?\d{4}`, text)
}

# Rule 15: Credit card detection in output
allow if {
    input.response
    response_text := input.response.json.choices[0].message.content
    
    # Check for credit card patterns (simplified)
    not contains_credit_card_pattern(response_text)
}

contains_credit_card_pattern(text) if {
    # 16-digit numbers (simplified credit card check)
    regex.match(`\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}`, text)
}

# Rule 16: Code injection prevention in output
allow if {
    input.response
    response_text := input.response.json.choices[0].message.content
    
    # Prevent SQL injection patterns in output
    not contains_sql_injection(response_text)
}

contains_sql_injection(text) if {
    lower_text := lower(text)
    sql_patterns := ["drop table", "delete from", "update set", "insert into", "'; --"]
    pattern := sql_patterns[_]
    contains(lower_text, pattern)
}

# Rule 17: Admin override - always allow
allow if {
    input.response
    has_min_role(input.metadata, "admin")
}

# Rule 18: Audit mode for specific users (always allow but log)
allow if {
    input.response
    input.metadata.user_email == "audit-user@truefoundry.com"
    # In production, this would log the response for review
}
# ============================================================================
# POLICY VIOLATIONS & METADATA
# ============================================================================

# Collect all violations for detailed error messages
violations contains msg if {
    input.response
    response_text := input.response.json.choices[0].message.content
    contains_sensitive_content(response_text)
    msg := "Response contains sensitive keywords"
}

violations contains msg if {
    input.response
    response_text := input.response.json.choices[0].message.content
    contains_toxic_content(response_text)
    msg := "Response contains toxic/harmful content"
}

violations contains msg if {
    input.response
    response_text := input.response.json.choices[0].message.content
    contains_email_pattern(response_text)
    msg := "Response contains email addresses"
}

violations contains msg if {
    input.response
    response_text := input.response.json.choices[0].message.content
    contains_phone_pattern(response_text)
    msg := "Response contains phone numbers"
}

violations contains msg if {
    input.response
    response_text := input.response.json.choices[0].message.content
    contains_credit_card_pattern(response_text)
    msg := "Response contains credit card numbers"
}

violations contains msg if {
    not input.response
    not has_min_role(input.metadata, "viewer")
    msg := "Insufficient role level - minimum 'viewer' required"
}

violations contains msg if {
    not input.response
    not is_allowed_tenant(input.metadata.tenant_name)
    msg := sprintf("Tenant '%s' is not in allowed list", [input.metadata.tenant_name])
}