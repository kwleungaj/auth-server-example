package com.wingsofpear.authserverexample.auth.controller;

import com.wingsofpear.authserverexample.auth.dto.UserResponseDTO;
import com.wingsofpear.authserverexample.auth.service.UserService;
import com.wingsofpear.authserverexample.common.dto.ApiResponseDTO;
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
}
