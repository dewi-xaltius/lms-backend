package com.example.lms_backend.payload.response;

import java.util.List;

/**
 * DTO for returning user information to the client.
 * Excludes sensitive data like passwords or tokens not relevant for general user info display.
 */
public record UserResponse(
    Long id,
    String username,
    String firstName,
    String lastName,
    String email,
    List<String> roles // List of role names (e.g., "ROLE_MEMBER", "ROLE_LIBRARIAN")
) {
    // No custom constructor needed if using a record and all fields are passed.
}
