package com.example.lms_backend.controller;

import com.example.lms_backend.entity.Role;
import com.example.lms_backend.entity.User;
import com.example.lms_backend.payload.request.LoginRequest;
import com.example.lms_backend.payload.request.SignupRequest;
import com.example.lms_backend.payload.response.JwtResponse;
import com.example.lms_backend.payload.response.MessageResponse;
import com.example.lms_backend.repository.UserRepository;
import com.example.lms_backend.security.jwt.JwtUtils;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Controller for handling authentication requests like login and registration.
 */
@CrossOrigin(origins = "*", maxAge = 3600) // Allows cross-origin requests, useful for development
@RestController
@RequestMapping("/api/auth") // Base path for all endpoints in this controller
public class AuthController {

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    JwtUtils jwtUtils;

    /**
     * Handles user sign-in requests.
     * Authenticates the user and returns a JWT upon success.
     *
     * @param loginRequest The login request payload containing username and password.
     * @return ResponseEntity containing JwtResponse with token and user details, or an error response.
     */
    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

        // Authenticate the user with username and password
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.username(), loginRequest.password()));

        // Set the authentication object in the SecurityContext
        SecurityContextHolder.getContext().setAuthentication(authentication);
        // Generate JWT token
        String jwt = jwtUtils.generateJwtToken(authentication);

        // Get UserDetails from the authentication object
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        // Get user roles
        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        // Retrieve the full User entity to get the ID and email
        // Note: UserDetails typically only has username, password, authorities.
        // We need to fetch the User entity from the database for more details.
        User user = userRepository.findByUsername(userDetails.getUsername())
            .orElseThrow(() -> new RuntimeException("Error: User not found after authentication."));


        // Return the JWT and user details in the response
        return ResponseEntity.ok(new JwtResponse(jwt,
                user.getId(),
                userDetails.getUsername(),
                user.getEmail(), // Assuming User entity has getEmail()
                roles));
    }

    /**
     * Handles user registration requests.
     * Creates a new user account.
     *
     * @param signUpRequest The signup request payload containing user details.
     * @return ResponseEntity with a success or error message.
     */
    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
        // Check if username is already taken
        if (userRepository.existsByUsername(signUpRequest.username())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Username is already taken!"));
        }

        // Check if email is already taken
        if (userRepository.existsByEmail(signUpRequest.email())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Email is already in use!"));
        }

        // Create new user's account
        User user = new User(
                signUpRequest.firstName(),
                signUpRequest.lastName(),
                signUpRequest.username(),
                signUpRequest.email(),
                encoder.encode(signUpRequest.password()) // Encode the password
        );

        Set<String> strRoles = signUpRequest.roles();
        Set<Role> roles = new HashSet<>();

        if (strRoles == null || strRoles.isEmpty()) {
            // Default role if none provided
            roles.add(Role.ROLE_MEMBER);
        } else {
            strRoles.forEach(role -> {
                switch (role.toLowerCase()) {
                    case "librarian":
                    case "admin": // Alias for librarian
                        roles.add(Role.ROLE_LIBRARIAN);
                        break;
                    case "member":
                        roles.add(Role.ROLE_MEMBER);
                        break;
                    default:
                        // You might want to throw an exception or assign a default role for unknown roles
                        System.out.println("Warning: Unknown role '" + role + "' specified. Assigning default MEMBER role.");
                        roles.add(Role.ROLE_MEMBER);
                }
            });
        }
        user.setRoles(roles);
        userRepository.save(user);

        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }
}
