package com.wingsofpear.authserverexample.auth.controller;

import com.wingsofpear.authserverexample.auth.dto.*;
import com.wingsofpear.authserverexample.auth.service.AuthService;
import com.wingsofpear.authserverexample.common.dto.ApiResponseDTO;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;

    @PostMapping("/signup")
    public ResponseEntity<ApiResponseDTO<Boolean>> signup(@Valid @RequestBody SignupRequestDTO req) {
        authService.signup(req);
        return ResponseEntity.ok(ApiResponseDTO.success(null));
    }

    @PostMapping("/otp/request")
    public ResponseEntity<ApiResponseDTO<Boolean>> requestOtp(@Valid @RequestBody OtpRequestDTO req) {
        authService.requestOtp(req);
        return ResponseEntity.ok(ApiResponseDTO.success(null));
    }

    @PostMapping("/otp/login")
    public ResponseEntity<ApiResponseDTO<JwtResponse>> loginWithOtp(@Valid @RequestBody OtpLoginRequestDTO otpLoginRequestDTO) {
        return ResponseEntity.ok(ApiResponseDTO.success(authService.loginWithOtp(otpLoginRequestDTO)));
    }

    @PostMapping("/logout/rt")
    public ResponseEntity<ApiResponseDTO<Boolean>> logoutOneSessionByRefreshToken(
            @Valid @RequestBody LogoutByRTRequestDTO refreshTokenDTO) {
        authService.logoutByRT(refreshTokenDTO);
        return ResponseEntity.ok(ApiResponseDTO.success(null));
    }

    @PostMapping("/logout/at")
    public ResponseEntity<ApiResponseDTO<Boolean>> logoutOneSessionByAccessToken() {
        authService.logoutByAT();
        return ResponseEntity.ok(ApiResponseDTO.success(null));
    }

    @PostMapping("/logout/all")
    public ResponseEntity<ApiResponseDTO<Boolean>> logoutAllSession() {
        authService.logoutAll();
        return ResponseEntity.ok(ApiResponseDTO.success(null));
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<ApiResponseDTO<JwtResponse>> refreshToken(@Valid @RequestBody TokenRefreshRequestDTO request) {
        return ResponseEntity.ok(ApiResponseDTO.success(authService.refreshToken(request)));
    }
}
