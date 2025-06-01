package com.example.lms_backend.payload.response;

import java.util.List;

// Using a Java Record
public record JwtResponse(
    String token,
    String type, // e.g., "Bearer"
    Long id,
    String username,
    String firstName, // Added firstName
    String lastName,  // Added lastName
    String email,
    List<String> roles
) {
    // Custom constructor to set default type "Bearer"
    // This constructor needs to be updated to include firstName and lastName
    public JwtResponse(String token, Long id, String username, String firstName, String lastName, String email, List<String> roles) {
        this(token, "Bearer", id, username, firstName, lastName, email, roles);
    }
}
