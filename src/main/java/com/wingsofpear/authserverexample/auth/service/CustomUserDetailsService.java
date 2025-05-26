package com.wingsofpear.authserverexample.auth.service;

import com.wingsofpear.authserverexample.auth.dto.CustomUserDetails;
import com.wingsofpear.authserverexample.auth.entity.User;
import com.wingsofpear.authserverexample.auth.repository.UserRepository;
import com.wingsofpear.authserverexample.common.constant.SystemConstants;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.*;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepo;

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        log.info("CustomUserDetailsService.loadUserByUsername called with email: {}", email);

        verifyNotSystemUser(email, null);

        Optional<User> u = userRepo.findByEmailAndDeletedAtIsNull(email);
        if (u.isEmpty()) {
            throw new UsernameNotFoundException("User not found: " + email);
        }
        // todo: roles/authorities
        CustomUserDetails customUserDetails = new CustomUserDetails(u.get());

        log.info("User loaded with ID: {}", customUserDetails.getId());

        verifyNotSystemUser(null, customUserDetails.getId());

        log.info("UserDetails loaded successfully: {}", customUserDetails);

        return customUserDetails;
    }

    private void verifyNotSystemUser(String email, Long id) {
        if (SystemConstants.SYSTEM_USER_EMAIL.equals(email) || SystemConstants.SYSTEM_USER_ID.equals(id)) {
            log.warn("Attempted login with system user email rejected");
            throw new BadCredentialsException("System user cannot log in");
        }
    }
}

