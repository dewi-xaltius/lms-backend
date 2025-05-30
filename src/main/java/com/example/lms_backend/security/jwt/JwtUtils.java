package com.example.lms_backend.security.jwt;

import com.example.lms_backend.service.UserDetailsServiceImpl; // Assuming UserDetailsImpl is in this package
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException; // Correct import for SignatureException
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.security.Key;
import java.util.Date;

/**
 * Utility class for handling JWT operations: generation, validation, parsing.
 */
@Component // Marks this class as a Spring component, making it available for dependency injection
public class JwtUtils {
    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    // Injects the JWT secret key from application.properties
    @Value("${lms.app.jwtSecret}")
    private String jwtSecret;

    // Injects the JWT expiration time from application.properties
    @Value("${lms.app.jwtExpirationMs}")
    private int jwtExpirationMs;

    private Key key;

    // Initialize the key after properties are set
    @jakarta.annotation.PostConstruct
    public void init() {
        this.key = Keys.hmacShaKeyFor(jwtSecret.getBytes());
    }

    /**
     * Generates a JWT token for the given authentication object.
     * The username is extracted from the UserDetails principal.
     *
     * @param authentication The Spring Security Authentication object.
     * @return The generated JWT token as a String.
     */
    public String generateJwtToken(Authentication authentication) {
        UserDetails userPrincipal = (UserDetails) authentication.getPrincipal();

        return Jwts.builder()
                .setSubject((userPrincipal.getUsername())) // Set the username as the subject
                .setIssuedAt(new Date()) // Set the token issuance date
                .setExpiration(new Date((new Date()).getTime() + jwtExpirationMs)) // Set the token expiration date
                .signWith(key, SignatureAlgorithm.HS512) // Sign the token with the secret key using HS512 algorithm
                .compact(); // Build the token and serialize it to a compact, URL-safe string
    }

    /**
     * Extracts the username from a given JWT token.
     *
     * @param token The JWT token.
     * @return The username contained in the token.
     */
    public String getUserNameFromJwtToken(String token) {
        return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody().getSubject();
    }

    /**
     * Validates a given JWT token.
     * Checks for signature validity, expiration, malformation, and unsupported issues.
     *
     * @param authToken The JWT token to validate.
     * @return true if the token is valid, false otherwise.
     */
    public boolean validateJwtToken(String authToken) {
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(authToken);
            return true;
        } catch (SignatureException e) {
            logger.error("Invalid JWT signature: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        }

        return false;
    }

    /**
     * Parses the JWT from the Authorization header of an HTTP request.
     * Expects the header in the format "Bearer <token>".
     *
     * @param request The HttpServletRequest from which to extract the token.
     * @return The JWT string if found and valid, or null otherwise.
     */
    public String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader("Authorization");

        if (StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer ")) {
            return headerAuth.substring(7); // Extract token part after "Bearer "
        }
        return null;
    }
}
