package com.example.lms_backend.config; 

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Spring Security configuration class.
 * This class defines how security is handled for HTTP requests.
 */
@Configuration // Indicates that this class contains Spring configuration beans
@EnableWebSecurity // Enables Spring Security's web security support
public class SecurityConfig {

    /**
     * Defines a PasswordEncoder bean that uses BCrypt hashing.
     * This will be used to hash passwords before storing them and to verify passwords during login.
     * @return a BCryptPasswordEncoder instance
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Configures the security filter chain that applies to all HTTP requests.
     * @param http HttpSecurity to configure
     * @return the configured SecurityFilterChain
     * @throws Exception if an error occurs during configuration
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // Disable CSRF (Cross-Site Request Forgery) protection.
            // CSRF is less relevant for stateless REST APIs where authentication is done via tokens (like JWT).
            .csrf(csrf -> csrf.disable())

            // Configure session management to be stateless.
            // This means the server will not create or use HTTP sessions; each request must be authenticated independently (e.g., with a JWT).
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

            // Define authorization rules for HTTP requests.
            .authorizeHttpRequests(authorize -> authorize
                // Permit all requests to '/api/auth/**' (e.g., for login, registration endpoints that we will create).
                .requestMatchers("/api/auth/**").permitAll()
                // Any other request must be authenticated.
                .anyRequest().authenticated()
            );
            // More configurations like adding JWT filter will be added here later.

        return http.build();
    }
}
