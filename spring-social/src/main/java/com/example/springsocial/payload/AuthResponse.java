package com.example.springsocial.payload;





public class AuthResponse {
    private String accessToken;
    private String tokenType = "Bearer";
    private Long id;
	private String username;
	private String email;
	
    
	
	
	public AuthResponse(String accessToken) {
        this.accessToken = accessToken;
       
		
    }

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public String getTokenType() {
        return tokenType;
    }

    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
    }

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	
	
    
    
}
