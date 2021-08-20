package com.example.springsocial.payload;

import java.util.Set;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;

/**
 * Created by rajeevkumarsingh on 02/08/17.
 */

public class SignUpRequest {
    @NotBlank
    private String name;

    @NotBlank
    @Email
    private String email;
    
    private Set<String> role;

    @NotBlank
    private String password;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
    
    public Set<String> getRole() {
        return this.role;
      }
      
      public void setRole(Set<String> role) {
        this.role = role;
      }
}
