package com.example.lms_backend.security.jwt;

import com.example.lms_backend.service.UserDetailsServiceImpl;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Filter that intercepts incoming requests to validate JWT tokens from the Authorization header.
 * If a valid token is found, it sets the authentication in Spring Security's SecurityContext.
 */
@Component // Marks this class as a Spring component
public class AuthTokenFilter extends OncePerRequestFilter {

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private UserDetailsServiceImpl userDetailsService; // Ensure this matches your UserDetailsService implementation bean name/type

    private static final Logger logger = LoggerFactory.getLogger(AuthTokenFilter.class);

    /**
     * This method is executed for each incoming request.
     * It attempts to parse and validate a JWT from the Authorization header.
     * If successful, it sets the user's authentication in the SecurityContext.
     *
     * @param request     The incoming HTTP request.
     * @param response    The HTTP response.
     * @param filterChain The filter chain to proceed with.
     * @throws ServletException If a servlet-specific error occurs.
     * @throws IOException      If an I/O error occurs.
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        try {
            // 1. Parse JWT from the Authorization header
            String jwt = parseJwt(request);

            // 2. Validate the JWT
            if (jwt != null && jwtUtils.validateJwtToken(jwt)) {
                // 3. Extract username from JWT
                String username = jwtUtils.getUserNameFromJwtToken(jwt);

                // 4. Load UserDetails by username
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);

                // 5. Create an Authentication object
                // UsernamePasswordAuthenticationToken is a common implementation of Authentication.
                // It's used here because we have UserDetails; credentials (password) are not needed at this stage as the JWT is the proof of auth.
                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(
                                userDetails,
                                null, // Credentials - not needed for JWT-based auth as token is already validated
                                userDetails.getAuthorities()); // User's roles/permissions

                // 6. Set details for the authentication (e.g., IP address, session ID - though session is stateless for us)
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // 7. Set the Authentication object in the SecurityContext
                // This effectively authenticates the user for the current request.
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        } catch (Exception e) {
            // Log any errors during JWT processing
            logger.error("Cannot set user authentication: {}", e.getMessage());
            // Note: We don't explicitly send an error response here.
            // If authentication is not set, and the resource is protected,
            // Spring Security's ExceptionTranslationFilter will eventually trigger the AuthEntryPointJwt.
        }

        // Continue with the filter chain
        filterChain.doFilter(request, response);
    }

    /**
     * Helper method to parse the JWT from the "Authorization" header.
     * The token is expected to be in the format "Bearer <token>".
     *
     * @param request The HttpServletRequest.
     * @return The JWT string if present and correctly formatted, otherwise null.
     */
    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader("Authorization");

        if (StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer ")) {
            return headerAuth.substring(7); // Remove "Bearer " prefix
        }

        return null;
    }
}
