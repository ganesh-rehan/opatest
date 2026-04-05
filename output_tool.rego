package mcp_output                                                                                                                                                                  
                                                                                                                                                                                                          
  default allow = true                                                                                                                                                                                    
                                                                                                                                                                                                          
  allow = false if{                                                                                                                                                                                         
      input.metadata.mcp_server_name == "deepwiki-sucecsui"
      content := input.request.content[0].text
      contains(content, "microsoft/vscode")                                                                                                                                                               
  }
                                                                                                                                                                                                          
  result := {                
      "allow": allow,
      "desc": "Blocked: response contains microsoft/vscode content from deepwiki",
  }