package com.example.lms_backend.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

/**
 * Controller for testing access to protected resources.
 */
@CrossOrigin(origins = "*", maxAge = 3600) // Allows cross-origin requests
@RestController
@RequestMapping("/api/test") // Base path for all test endpoints
public class TestController {

    /**
     * A public test endpoint (for comparison, not strictly needed for JWT test).
     * @return A simple success message.
     */
    @GetMapping("/all")
    public ResponseEntity<String> allAccess() {
        return ResponseEntity.ok("Public Content - Everyone can see this.");
    }

    /**
     * A protected endpoint that requires authentication.
     * It will return a message including the authenticated user's username.
     * @return A success message if authenticated, or triggers 401 if not.
     */
    @GetMapping("/hello")
    public ResponseEntity<?> userAccess() {
        // Get the authentication object from the SecurityContext
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated() || "anonymousUser".equals(authentication.getPrincipal())) {
            // This case should ideally be handled by Spring Security's filter chain leading to AuthEntryPointJwt
            // if .anyRequest().authenticated() is in effect and no valid JWT was provided.
            // However, having an explicit check can be useful for clarity or specific logic.
            return ResponseEntity.status(401).body("Unauthorized: You need to be logged in to access this resource.");
        }

        Object principal = authentication.getPrincipal();
        String username;

        if (principal instanceof UserDetails) {
            username = ((UserDetails) principal).getUsername();
        } else {
            username = principal.toString(); // Fallback if principal is not UserDetails (e.g. just a String)
        }

        Map<String, String> response = new HashMap<>();
        response.put("message", "Hello, " + username + "! This is a protected resource.");
        response.put("note", "You have successfully accessed a JWT-protected endpoint.");
        
        return ResponseEntity.ok(response);
    }

    /**
     * Example of an endpoint that requires a specific role (e.g., LIBRARIAN).
     * This uses method-level security with @PreAuthorize.
     * Make sure @EnableMethodSecurity is on your SecurityConfig.
     * @return A success message if user has the required role.
     */
    @GetMapping("/librarian")
    @PreAuthorize("hasRole('LIBRARIAN')") // Requires ROLE_LIBRARIAN
    public ResponseEntity<String> librarianAccess() {
        return ResponseEntity.ok("Librarian Content - Only users with ROLE_LIBRARIAN can see this.");
    }

     /**
     * Example of an endpoint that requires a specific role (e.g., MEMBER).
     * This uses method-level security with @PreAuthorize.
     * @return A success message if user has the required role.
     */
    @GetMapping("/member")
    @PreAuthorize("hasRole('MEMBER')") // Requires ROLE_MEMBER
    public ResponseEntity<String> memberAccess() {
        return ResponseEntity.ok("Member Content - Only users with ROLE_MEMBER can see this.");
    }
}
