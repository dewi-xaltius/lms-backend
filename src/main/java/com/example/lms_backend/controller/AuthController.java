package com.example.lms_backend.controller;

import com.example.lms_backend.entity.Role; // Assuming Role is in .entity package
import com.example.lms_backend.entity.User; // Assuming User is in .entity package
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
@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
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

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.username(), loginRequest.password()));

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        // Retrieve the full User entity to get ID, email, firstName, and lastName
        User user = userRepository.findByUsername(userDetails.getUsername())
                .orElseThrow(() -> new RuntimeException("Error: User not found after authentication. This should not happen."));

        // Return the JWT and updated user details in the response
        return ResponseEntity.ok(new JwtResponse(jwt,
                user.getId(),
                user.getUsername(), // Or userDetails.getUsername() - should be the same
                user.getFirstName(), // Get firstName from User entity
                user.getLastName(),  // Get lastName from User entity
                user.getEmail(),
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
        if (userRepository.existsByUsername(signUpRequest.username())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Username is already taken!"));
        }

        if (userRepository.existsByEmail(signUpRequest.email())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Email is already in use!"));
        }

        User user = new User(
                signUpRequest.firstName(),
                signUpRequest.lastName(),
                signUpRequest.username(),
                signUpRequest.email(),
                encoder.encode(signUpRequest.password())
        );

        Set<String> strRoles = signUpRequest.roles();
        Set<Role> domainRoles = new HashSet<>(); // Renamed to avoid conflict with 'roles' list from signin

        if (strRoles == null || strRoles.isEmpty()) {
            domainRoles.add(Role.ROLE_MEMBER);
        } else {
            strRoles.forEach(role -> {
                switch (role.toLowerCase()) {
                    case "librarian":
                    case "admin":
                        domainRoles.add(Role.ROLE_LIBRARIAN);
                        break;
                    case "member":
                        domainRoles.add(Role.ROLE_MEMBER);
                        break;
                    default:
                        System.out.println("Warning: Unknown role '" + role + "' specified during signup. Assigning default MEMBER role.");
                        domainRoles.add(Role.ROLE_MEMBER);
                }
            });
        }
        user.setRoles(domainRoles);
        userRepository.save(user);

        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }
}
