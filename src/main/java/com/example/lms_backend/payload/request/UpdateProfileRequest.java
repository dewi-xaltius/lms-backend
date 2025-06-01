package com.example.lms_backend.payload.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Size;

// Using a Java Record for a simple, immutable data carrier.
// Fields are optional in terms of @NotBlank because a user might want to update only one field.
// Validation for at least one field being present, or specific business rules,
// can be handled in the service layer if needed.
public record UpdateProfileRequest(
    @Size(min = 2, max = 50, message = "First name must be between 2 and 50 characters")
    String firstName,

    @Size(min = 2, max = 50, message = "Last name must be between 2 and 50 characters")
    String lastName,

    @Size(max = 50, message = "Email cannot be longer than 50 characters")
    @Email(message = "Email should be valid")
    String email
) {
    // Note: With records, accessor methods (firstName(), lastName(), email()) are automatically generated.
    // No explicit @NotBlank here, assuming partial updates are allowed (e.g., user updates only email).
    // If all fields were required for an update, you'd add @NotBlank.
    // Alternatively, the service layer can check if at least one field is provided.
}
