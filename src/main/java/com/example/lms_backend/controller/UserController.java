package com.example.lms_backend.controller;

import com.example.lms_backend.entity.User;
import com.example.lms_backend.payload.request.UpdateProfileRequest;
import com.example.lms_backend.payload.response.MessageResponse;
import com.example.lms_backend.payload.response.JwtResponse; 
import com.example.lms_backend.payload.response.UserResponse; 
import com.example.lms_backend.repository.UserRepository;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize; // Keep for other methods
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/users")
public class UserController {

    private static final Logger logger = LoggerFactory.getLogger(UserController.class);

    @Autowired
    private UserRepository userRepository;

    @PutMapping("/me/profile")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> updateMyProfile(@Valid @RequestBody UpdateProfileRequest updateProfileRequest) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String currentUsername = authentication.getName();
        User currentUser = userRepository.findByUsername(currentUsername)
                .orElseThrow(() -> new RuntimeException("Error: User not found. This should not happen if authenticated."));

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

    @GetMapping("/me/profile")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<UserResponse> getMyProfile() {
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
     * (Librarian) Gets a list of all users.
     * Security for this endpoint is handled by URL-based rules in SecurityConfig.
     * @return ResponseEntity with a list of UserResponse objects.
     */
    @GetMapping // Mapped to GET /api/users
    // No @PreAuthorize annotation here for this approach; SecurityConfig will handle role check
    public ResponseEntity<?> getAllUsers() {
        // This log is crucial for confirming the method is entered.
        logger.info("UserController (getAllUsers): METHOD ENTERED. Attempting to fetch all users.");
        // The SecurityContextHolder should have the authentication object set by AuthTokenFilter.
        // The URL-based rule `.requestMatchers(HttpMethod.GET, "/api/users").hasRole("LIBRARIAN")` 
        // in SecurityConfig should have already enforced the role check before this method is called.
        
        try {
            List<User> users = userRepository.findAll();
            logger.debug("UserController: Found {} users in the database.", users.size());

            List<UserResponse> userResponses = users.stream()
                .map(user -> {
                    // logger.debug("UserController: Mapping user: {}", user.getUsername()); // Optional: more verbose logging
                    List<String> roleNames = user.getRoles().stream()
                                                 .map(roleEnum -> roleEnum.name()) // Make sure Role enum is imported if not in same package
                                                 .collect(Collectors.toList());
                    return new UserResponse(
                        user.getId(),
                        user.getUsername(),
                        user.getFirstName(),
                        user.getLastName(),
                        user.getEmail(),
                        roleNames
                    );
                })
                .collect(Collectors.toList());
            
            logger.info("UserController: Successfully fetched and mapped {} users.", userResponses.size());
            return ResponseEntity.ok(userResponses);
        } catch (Exception e) {
            logger.error("UserController: Error fetching all users: {}", e.getMessage(), e); // Log the full exception
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                                 .body(new MessageResponse("Error: Could not fetch users. " + e.getMessage()));
        }
    }
}
