package com.wingsofpear.authserverexample.auth.service;

import com.wingsofpear.authserverexample.auth.dto.UpdateUserRequestDTO;
import com.wingsofpear.authserverexample.auth.dto.UserResponseDTO;

public interface UserService {
    UserResponseDTO getUser();

    void updateUser(UpdateUserRequestDTO updateUserRequestDTO);
}