package com.wingsofpear.authserverexample.auth.controller;

import com.wingsofpear.authserverexample.auth.dto.UpdateUserRequestDTO;
import com.wingsofpear.authserverexample.auth.dto.UserResponseDTO;
import com.wingsofpear.authserverexample.auth.service.UserService;
import com.wingsofpear.authserverexample.common.dto.ApiResponseDTO;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;

    @GetMapping("/me")
    public ResponseEntity<ApiResponseDTO<UserResponseDTO>> getUser() {
        UserResponseDTO userResponseDTO = userService.getUser();
        return ResponseEntity.ok(ApiResponseDTO.success(userResponseDTO));
    }

    @PostMapping("/me")
    public ResponseEntity<ApiResponseDTO<Void>> updateUser(@Valid @RequestBody UpdateUserRequestDTO updateUserRequestDTO) {
        userService.updateUser(updateUserRequestDTO);
        return ResponseEntity.ok(ApiResponseDTO.success(null));
    }
}
