package com.example.lms_backend.payload.request;

import jakarta.validation.constraints.NotBlank;

// Using a Java Record for a simple, immutable data carrier
public record LoginRequest(
    @NotBlank(message = "Username cannot be blank")
    String username,

    @NotBlank(message = "Password cannot be blank")
    String password
) {
}
