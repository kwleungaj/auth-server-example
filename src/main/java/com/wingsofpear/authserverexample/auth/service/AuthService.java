package com.wingsofpear.authserverexample.auth.service;

import com.wingsofpear.authserverexample.auth.dto.*;
import jakarta.validation.Valid;

public interface AuthService {
    void signup(SignupRequestDTO req);
    JwtResponse loginWithOtp(@Valid OtpLoginRequestDTO req);
    JwtResponse refreshToken(TokenRefreshRequestDTO request);

    void requestOtp(OtpRequestDTO req);

    void logoutByRT(LogoutByRTRequestDTO refreshTokenDTO);

    void logoutByAT();

    void logoutAll();
}
