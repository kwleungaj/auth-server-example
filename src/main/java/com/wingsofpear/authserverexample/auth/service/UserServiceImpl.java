package com.wingsofpear.authserverexample.auth.service;

import com.wingsofpear.authserverexample.auth.dto.UpdateUserRequestDTO;
import com.wingsofpear.authserverexample.auth.dto.UserResponseDTO;
import com.wingsofpear.authserverexample.auth.entity.User;
import com.wingsofpear.authserverexample.auth.repository.UserRepository;
import com.wingsofpear.authserverexample.common.util.SessionUtil;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

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

    @Override
    public void updateUser(UpdateUserRequestDTO updateUserRequestDTO) {
        String email = SessionUtil.getEmail();
        String firstName = updateUserRequestDTO.getFirstName();
        String lastName = updateUserRequestDTO.getLastName();
        User u = userRepo
                .findByEmailAndDeletedAtIsNull(email)
                .orElseThrow(() -> new EntityNotFoundException("User not found"));

        if (StringUtils.hasText(firstName)) {
            u.setFirstName(firstName);
        }
        if (StringUtils.hasText(lastName)) {
            u.setLastName(lastName);
        }
        userRepo.save(u);
    }

}
