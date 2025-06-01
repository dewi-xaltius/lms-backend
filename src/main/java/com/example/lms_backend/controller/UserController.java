package com.example.lms_backend.controller;

import com.example.lms_backend.entity.User;
import com.example.lms_backend.payload.request.UpdateProfileRequest;
import com.example.lms_backend.payload.response.MessageResponse; // Optional: for success message
// Or return the updated User object, which might require a UserResponse DTO or modification to JwtResponse
import com.example.lms_backend.payload.response.JwtResponse; // Reusing JwtResponse for updated user info
import com.example.lms_backend.repository.UserRepository;
import com.example.lms_backend.security.jwt.JwtUtils; // Not strictly needed here unless re-issuing token
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.access.prepost.PreAuthorize; // For method-level security
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/users") // Base path for user-related operations
public class UserController {

    @Autowired
    private UserRepository userRepository;

    // Optional: Inject PasswordEncoder if you were allowing password updates here
    // @Autowired
    // private PasswordEncoder passwordEncoder;

    /**
     * Updates the profile of the currently authenticated user.
     *
     * @param updateProfileRequest The request body containing fields to update.
     * @return ResponseEntity with the updated user information or an error.
     */
    @PutMapping("/me/profile")
    @PreAuthorize("isAuthenticated()") // Ensures the user is logged in
    public ResponseEntity<?> updateMyProfile(@Valid @RequestBody UpdateProfileRequest updateProfileRequest) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String currentUsername = authentication.getName();

        Optional<User> userOptional = userRepository.findByUsername(currentUsername);

        if (userOptional.isEmpty()) {
            // This should ideally not happen if @PreAuthorize("isAuthenticated()") is effective
            // and the token corresponds to a valid user.
            return ResponseEntity.status(404).body(new MessageResponse("Error: User not found."));
        }

        User currentUser = userOptional.get();
        boolean updated = false;

        // Update firstName if provided
        if (updateProfileRequest.firstName() != null && !updateProfileRequest.firstName().isBlank()) {
            currentUser.setFirstName(updateProfileRequest.firstName());
            updated = true;
        }

        // Update lastName if provided
        if (updateProfileRequest.lastName() != null && !updateProfileRequest.lastName().isBlank()) {
            currentUser.setLastName(updateProfileRequest.lastName());
            updated = true;
        }

        // Update email if provided
        if (updateProfileRequest.email() != null && !updateProfileRequest.email().isBlank()) {
            // Check if the new email is already taken by another user
            if (!currentUser.getEmail().equals(updateProfileRequest.email()) &&
                userRepository.existsByEmail(updateProfileRequest.email())) {
                return ResponseEntity.badRequest().body(new MessageResponse("Error: Email is already in use by another account!"));
            }
            currentUser.setEmail(updateProfileRequest.email());
            updated = true;
        }

        if (!updated) {
            return ResponseEntity.ok(new MessageResponse("No changes provided for profile update."));
        }

        User updatedUser = userRepository.save(currentUser);

        // Option 1: Return a simple success message
        // return ResponseEntity.ok(new MessageResponse("Profile updated successfully!"));

        // Option 2: Return the updated user information.
        // We can reuse JwtResponse structure but without a new token, or create a dedicated UserProfileResponse.
        // For simplicity, let's re-fetch roles and construct something similar to JwtResponse,
        // but ideally, you might not want to include the token here unless it's re-issued.
        // Let's return the updated fields in a way the frontend can use to update its context.
        // Re-using JwtResponse structure, but token field will be null or a dummy value as we are not re-issuing.
        // A better approach would be a dedicated UserProfileResponse DTO.
        List<String> roles = updatedUser.getRoles().stream()
                                 .map(roleEnum -> roleEnum.name())
                                 .collect(Collectors.toList());
        
        // For simplicity now, let's return a limited set of updated data
        // or the frontend can just refetch user data/trust the context update.
        // Returning a structure similar to what AuthContext expects for the 'user' object.
        return ResponseEntity.ok(new JwtResponse(
            null, // No new token is issued for profile update
            "User Profile Updated", // Using type field for status message
            updatedUser.getId(),
            updatedUser.getUsername(),
            updatedUser.getFirstName(),
            updatedUser.getLastName(),
            updatedUser.getEmail(),
            roles
        ));
    }

    // You could also add an endpoint to get the current user's profile
    @GetMapping("/me/profile")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> getMyProfile() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String currentUsername = authentication.getName();

        User currentUser = userRepository.findByUsername(currentUsername)
            .orElseThrow(() -> new RuntimeException("Error: User not found, though authenticated. Inconsistency."));
        
        List<String> roles = currentUser.getRoles().stream()
                                 .map(roleEnum -> roleEnum.name())
                                 .collect(Collectors.toList());

        // Similar to above, returning user details.
        return ResponseEntity.ok(new JwtResponse(
            null, // No token needed for just fetching profile
            "User Profile Data",
            currentUser.getId(),
            currentUser.getUsername(),
            currentUser.getFirstName(),
            currentUser.getLastName(),
            currentUser.getEmail(),
            roles
        ));
    }
}
