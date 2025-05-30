package com.example.lms_backend.payload.response;

import java.util.List;

// Using a Java Record
public record JwtResponse(
    String token,
    String type, // e.g., "Bearer"
    Long id,
    String username,
    String email,
    List<String> roles
) {
    // Custom constructor to set default type "Bearer"
    public JwtResponse(String token, Long id, String username, String email, List<String> roles) {
        this(token, "Bearer", id, username, email, roles);
    }
}
