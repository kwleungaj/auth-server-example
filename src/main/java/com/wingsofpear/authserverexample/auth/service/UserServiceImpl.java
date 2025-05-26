package com.wingsofpear.authserverexample.auth.service;

import com.wingsofpear.authserverexample.auth.dto.UserResponseDTO;
import com.wingsofpear.authserverexample.auth.entity.User;
import com.wingsofpear.authserverexample.auth.repository.UserRepository;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepo;

    @Override
    public UserResponseDTO getUser() {
        String email = SecurityContextHolder.getContext().getAuthentication().getName();
        User u = userRepo
                .findByEmailAndDeletedAtIsNull(email)
                .orElseThrow(() -> new EntityNotFoundException("User not found."));
        return new UserResponseDTO(u);
    }

}
