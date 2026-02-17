# FROM openpolicyagent/opa:latest

# # Set working directory
# WORKDIR /policies

# # Copy all policy files
# COPY authz_team_allow.rego .
# COPY authz_team_deny.rego .
# COPY policy_bearer.rego .
# COPY policy_mcp.rego .
# COPY policy_req.rego .
# COPY mcp_fetch.rego .

# # Expose OPA server port
# EXPOSE 8181

# # Run OPA server and load ALL policies
# CMD [
#     "run", \
#      "--server", \
#      "--addr", ":8181", \
#      "--log-level", "info", \
#      "/policies/authz_team_allow.rego", \
#      "/policies/authz_team_deny.rego", \
#      "/policies/policy_bearer.rego", \
#      "/policies/policy_mcp.rego", \
#      "/policies/policy_req.rego"
#     ]

FROM openpolicyagent/opa:latest
WORKDIR /policies

# Expose OPA server port
EXPOSE 8181

# Run OPA server watching the mounted policies directory
CMD ["run", \
     "--server", \
     "--addr", ":8181", \
     "--log-level", "info", \
     "--watch", \
     "/policies"]