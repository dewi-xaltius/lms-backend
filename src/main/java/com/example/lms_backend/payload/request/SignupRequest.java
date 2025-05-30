package com.example.lms_backend.payload.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import java.util.Set;

// Using a Java Record
public record SignupRequest(
    @NotBlank(message = "First name cannot be blank")
    @Size(min = 2, max = 50, message = "First name must be between 2 and 50 characters")
    String firstName,

    @NotBlank(message = "Last name cannot be blank")
    @Size(min = 2, max = 50, message = "Last name must be between 2 and 50 characters")
    String lastName,

    @NotBlank(message = "Username cannot be blank")
    @Size(min = 3, max = 20, message = "Username must be between 3 and 20 characters")
    String username,

    @NotBlank(message = "Email cannot be blank")
    @Size(max = 50, message = "Email cannot be longer than 50 characters")
    @Email(message = "Email should be valid")
    String email,

    @NotBlank(message = "Password cannot be blank")
    @Size(min = 6, max = 40, message = "Password must be between 6 and 40 characters")
    String password,

    // Roles can be specified during signup.
    // We'll map these strings (e.g., "member", "librarian") to our Role enums in the service layer.
    // For self-registration, this might often be defaulted to "member".
    Set<String> roles
) {
}
