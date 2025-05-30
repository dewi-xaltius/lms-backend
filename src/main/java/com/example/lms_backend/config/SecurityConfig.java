package com.example.lms_backend.config; // Or your chosen package for configuration

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration; // Import this
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
     * Exposes the AuthenticationManager as a Spring bean.
     * This manager is responsible for authenticating users.
     *
     * @param authenticationConfiguration The configuration from which to get the AuthenticationManager.
     * @return The AuthenticationManager bean.
     * @throws Exception If an error occurs while obtaining the AuthenticationManager.
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
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
            .csrf(csrf -> csrf.disable())

            // Configure session management to be stateless.
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
