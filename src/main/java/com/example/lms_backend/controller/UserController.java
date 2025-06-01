package com.example.lms_backend.controller;

import com.example.lms_backend.entity.User;
import com.example.lms_backend.payload.request.UpdateProfileRequest;
import com.example.lms_backend.payload.response.MessageResponse;
import com.example.lms_backend.payload.response.JwtResponse; // Still used for updateMyProfile response for now
import com.example.lms_backend.payload.response.UserResponse; // New DTO for user lists/details
import com.example.lms_backend.repository.UserRepository;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/users") // Base path for user-related operations
// Note: For admin-specific user management, you might consider a separate /api/admin/users path or controller
public class UserController {

    @Autowired
    private UserRepository userRepository;

    /**
     * Updates the profile of the currently authenticated user.
     * @param updateProfileRequest The request body containing fields to update.
     * @return ResponseEntity with the updated user information or an error.
     */
    @PutMapping("/me/profile")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> updateMyProfile(@Valid @RequestBody UpdateProfileRequest updateProfileRequest) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String currentUsername = authentication.getName();
        User currentUser = userRepository.findByUsername(currentUsername)
                .orElseThrow(() -> new RuntimeException("Error: User not found."));

        boolean updated = false;
        if (updateProfileRequest.firstName() != null && !updateProfileRequest.firstName().isBlank()) {
            currentUser.setFirstName(updateProfileRequest.firstName());
            updated = true;
        }
        if (updateProfileRequest.lastName() != null && !updateProfileRequest.lastName().isBlank()) {
            currentUser.setLastName(updateProfileRequest.lastName());
            updated = true;
        }
        if (updateProfileRequest.email() != null && !updateProfileRequest.email().isBlank()) {
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
        List<String> roles = updatedUser.getRoles().stream().map(roleEnum -> roleEnum.name()).collect(Collectors.toList());
        return ResponseEntity.ok(new JwtResponse(null, "User Profile Updated", updatedUser.getId(),
                updatedUser.getUsername(), updatedUser.getFirstName(), updatedUser.getLastName(),
                updatedUser.getEmail(), roles));
    }

    /**
     * Gets the profile of the currently authenticated user.
     * @return ResponseEntity with the user's profile information.
     */
    @GetMapping("/me/profile")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<UserResponse> getMyProfile() { // Changed return type to UserResponse
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String currentUsername = authentication.getName();
        User currentUser = userRepository.findByUsername(currentUsername)
            .orElseThrow(() -> new RuntimeException("Error: User not found, though authenticated."));
        
        List<String> roles = currentUser.getRoles().stream().map(roleEnum -> roleEnum.name()).collect(Collectors.toList());
        UserResponse userResponse = new UserResponse(currentUser.getId(), currentUser.getUsername(),
                currentUser.getFirstName(), currentUser.getLastName(), currentUser.getEmail(), roles);
        return ResponseEntity.ok(userResponse);
    }

    /**
     * (Admin/Librarian) Gets a list of all users.
     * This endpoint is intended for users with ROLE_LIBRARIAN.
     * @return ResponseEntity with a list of UserResponse objects.
     */
    @GetMapping
    @PreAuthorize("hasRole('LIBRARIAN')") // Only librarians can access this
    public ResponseEntity<List<UserResponse>> getAllUsers() {
        List<User> users = userRepository.findAll(); // Fetches all users
        List<UserResponse> userResponses = users.stream()
            .map(user -> new UserResponse(
                user.getId(),
                user.getUsername(),
                user.getFirstName(),
                user.getLastName(),
                user.getEmail(),
                user.getRoles().stream().map(roleEnum -> roleEnum.name()).collect(Collectors.toList())
            ))
            .collect(Collectors.toList());
        return ResponseEntity.ok(userResponses);
    }

    // We will add GET /api/users/{id}, PUT /api/users/{id}, DELETE /api/users/{id} for librarians next.
}
