package com.example.lms_backend.service;

import com.example.lms_backend.entity.User;
import com.example.lms_backend.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Set;
import java.util.stream.Collectors;

/**
 * Service implementation for loading user-specific data.
 * This class is used by Spring Security to authenticate users.
 */
@Service // Marks this class as a Spring service component
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired // Injects an instance of UserRepository
    private UserRepository userRepository;

    /**
     * Loads a user by their username and converts it to a Spring Security UserDetails object.
     *
     * @param username the username identifying the user whose data is required.
     * @return a fully populated UserDetails object (never null)
     * @throws UsernameNotFoundException if the user could not be found or the user has no GrantedAuthority
     */
    @Override
    @Transactional // Ensures that operations within this method are part of a single database transaction (especially useful for lazy-loaded collections if any)
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // Retrieve the user from the database using the UserRepository
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with username: " + username));

        // Convert the user's roles (Set<Role>) to a Set of GrantedAuthority objects
        // Spring Security expects roles in the format 'ROLE_member', 'ROLE_admin', etc.
        // Our Role enum (ROLE_MEMBER, ROLE_LIBRARIAN) already follows this.
        Set<GrantedAuthority> authorities = user.getRoles().stream()
                .map(role -> new SimpleGrantedAuthority(role.name())) // role.name() will give "ROLE_MEMBER", "ROLE_LIBRARIAN"
                .collect(Collectors.toSet());

        // Create and return a Spring Security User object
        // This User object (from org.springframework.security.core.userdetails.User)
        // implements the UserDetails interface.
        return new org.springframework.security.core.userdetails.User(
                user.getUsername(),
                user.getPassword(),
                authorities);
    }
}
// This UserDetailsServiceImpl class is used by Spring Security to load user details during authentication.