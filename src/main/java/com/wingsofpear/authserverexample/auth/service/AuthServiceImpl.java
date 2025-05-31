package com.wingsofpear.authserverexample.auth.service;

import com.wingsofpear.authserverexample.auth.client.AuthClient;
import com.wingsofpear.authserverexample.auth.dto.*;
import com.wingsofpear.authserverexample.auth.entity.User;
import com.wingsofpear.authserverexample.auth.repository.UserRepository;
import com.wingsofpear.authserverexample.common.util.SessionUtil;
import jakarta.persistence.EntityNotFoundException;
import jakarta.transaction.Transactional;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.stereotype.Service;

import java.security.InvalidParameterException;
import java.time.Instant;
import java.util.Optional;

@Slf4j
@Service
public class AuthServiceImpl implements AuthService {
    private final UserRepository userRepo;
    private final CustomAuthorizationService authorizationService;
    private final AuthClient authClient;
    private final OtpService otpService;
    private final EmailService emailService;

    public AuthServiceImpl(UserRepository userRepo,
                           OAuth2AuthorizationService authorizationService,
                           AuthClient authClient,
                           OtpService otpService,
                           EmailService emailService
    ) {
        this.userRepo = userRepo;
        this.authorizationService = (CustomAuthorizationService) authorizationService;
        this.authClient = authClient;
        this.otpService = otpService;
        this.emailService = emailService;
    }

    @Override
    @Transactional
    public void signup(SignupRequestDTO req) {
        if (userRepo.findByEmailAndDeletedAtIsNull(req.getEmail()).isPresent()) {
            throw new InvalidParameterException("EMAIL_EXIST");
        }

        User u = new User();
        u.setEmail(req.getEmail());
        u.setFirstName(req.getFirstName());
        u.setLastName(req.getLastName());
        userRepo.save(u);
    }

    @Override
    public void requestOtp(OtpRequestDTO req) {
        String email = req.getEmail();
        if (!userRepo.existsByEmailAndDeletedAtIsNull(email)) {
            throw new EntityNotFoundException("User not found.");
        }
        String otp = otpService.requestOtp(email);
        emailService.sendOtp(email, otp);
    }

    @Override
    @Transactional
    public JwtResponse loginWithOtp(OtpLoginRequestDTO req) {
        log.info("Login attempt for user: {}", req.getEmail());

        OAuth2AccessTokenResponse response = authClient.loginWithOtp(req.getEmail(), req.getOtp());
        User user = userRepo
                .findByEmailAndDeletedAtIsNull(req.getEmail())
                .orElseThrow(() -> new EntityNotFoundException("User not found: " + req.getEmail()));
        user.setLastLoginAt(Instant.now());
        userRepo.save(user);

        log.info("Login successful for user: {}", req.getEmail());
        return new JwtResponse(response);
    }

    @Override
    public JwtResponse refreshToken(TokenRefreshRequestDTO req) {
        String refreshToken = req.getRefreshToken();
        log.info("Refresh token: {}", refreshToken);
        OAuth2AccessTokenResponse response = authClient.refreshToken(refreshToken);
        log.info("Refresh tokens successful");
        return new JwtResponse(response);
    }

    @Override
    public void logoutByRT(LogoutByRTRequestDTO refreshTokenDTO) {
        authClient.postRevokeTokenRequest(refreshTokenDTO.getRefreshToken());
        log.info("Logout by refresh token successful");
    }

    @Override
    public void logoutByAT() {
        String accessToken = SessionUtil.getAccessToken();
        OAuth2Authorization authorization =
                Optional.ofNullable(authorizationService.findByToken(accessToken, OAuth2TokenType.ACCESS_TOKEN))
                        .orElseThrow(() -> new EntityNotFoundException("Authorization not found. Please provide an existing access token"));
        authorizationService.remove(authorization);
    }

    @Override
    public void logoutAll() {
        String email = SessionUtil.getEmail();
        log.info("User email: {}", email);
        authorizationService.revokeAllByPrincipal(email);
    }
}
