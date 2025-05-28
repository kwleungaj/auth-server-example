package com.wingsofpear.authserverexample.auth.service;

import com.wingsofpear.authserverexample.auth.OtpAuthenticationToken;
import com.wingsofpear.authserverexample.auth.dto.*;
import com.wingsofpear.authserverexample.auth.entity.User;
import com.wingsofpear.authserverexample.auth.repository.UserRepository;
import com.wingsofpear.authserverexample.common.util.SessionUtil;
import jakarta.persistence.EntityNotFoundException;
import jakarta.transaction.Transactional;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.security.InvalidParameterException;
import java.time.Instant;

@Slf4j
@Service
public class AuthServiceImpl implements AuthService {
    private final UserRepository userRepo;
    private final CustomAuthorizationService authorizationService;
    private final RestTemplate restTemplate;
    private final OtpService otpService;
    private final EmailService emailService;

    public AuthServiceImpl(UserRepository userRepo,
                           OAuth2AuthorizationService authorizationService,
                           @Qualifier("oauth2RestTemplate") RestTemplate restTemplate,
                           OtpService otpService,
                           EmailService emailService
    ) {
        this.userRepo = userRepo;
        this.authorizationService = (CustomAuthorizationService) authorizationService;
        this.restTemplate = restTemplate;
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

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add(OAuth2ParameterNames.GRANT_TYPE, OtpAuthenticationToken.grantType.getValue());
        form.add("email", req.getEmail());
        form.add("otp", req.getOtp());
        form.add(OAuth2ParameterNames.CLIENT_ID, "mobile-client");
        form.add(OAuth2ParameterNames.CLIENT_SECRET, "secret");
        form.add(OAuth2ParameterNames.SCOPE, "read write");

        String url = "/oauth2/token";
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        HttpEntity<MultiValueMap<String, String>> tokenReq = new HttpEntity<>(form, headers);

        ResponseEntity<OAuth2AccessTokenResponse> tokenResp = restTemplate
                .postForEntity(url, tokenReq, OAuth2AccessTokenResponse.class);
        if (tokenResp.getBody() == null) {
            throw new RuntimeException("token is null");
        }

        User user = userRepo
                .findByEmailAndDeletedAtIsNull(req.getEmail())
                .orElseThrow(() -> new EntityNotFoundException("User not found: " + req.getEmail()));
        user.setLastLoginAt(Instant.now());
        userRepo.save(user);

        log.info("Login successful for user: {}", req.getEmail());
        return new JwtResponse(tokenResp.getBody());
    }

    @Override
    public JwtResponse refreshToken(TokenRefreshRequestDTO req) {
        String refreshToken = req.getRefreshToken();
        log.info("Refresh token: {}", refreshToken);

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add(OAuth2ParameterNames.GRANT_TYPE, OAuth2ParameterNames.REFRESH_TOKEN);
        form.add(OAuth2ParameterNames.REFRESH_TOKEN, refreshToken);
        form.add(OAuth2ParameterNames.CLIENT_ID, "mobile-client");
        form.add(OAuth2ParameterNames.CLIENT_SECRET, "secret");
        form.add(OAuth2ParameterNames.SCOPE, "read write");

        String url = "/oauth2/token";
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        HttpEntity<MultiValueMap<String, String>> tokenReq = new HttpEntity<>(form, headers);

        ResponseEntity<OAuth2AccessTokenResponse> tokenResp = restTemplate
                .postForEntity(url, tokenReq, OAuth2AccessTokenResponse.class);
        if (tokenResp.getBody() == null) {
            throw new RuntimeException("token is null");
        }

        log.info("Refresh tokens successful");
        return new JwtResponse(tokenResp.getBody());
    }

    @Override
    public void logoutByRT(LogoutByRTRequestDTO refreshTokenDTO) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add(OAuth2ParameterNames.TOKEN, refreshTokenDTO.getRefreshToken());
        form.add(OAuth2ParameterNames.TOKEN_TYPE_HINT, OAuth2ParameterNames.REFRESH_TOKEN);
        form.add(OAuth2ParameterNames.CLIENT_ID, "mobile-client");
        form.add(OAuth2ParameterNames.CLIENT_SECRET, "secret");

        String url = "/oauth2/revoke";
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        HttpEntity<MultiValueMap<String, String>> tokenReq = new HttpEntity<>(form, headers);

        restTemplate.postForEntity(url, tokenReq, Void.class);

        log.info("Logout by refresh token successful");
    }

    @Override
    public void logoutByAT() {
        String accessToken = SessionUtil.getAccessToken();
        OAuth2Authorization authorization =
                authorizationService.findByToken(accessToken, OAuth2TokenType.ACCESS_TOKEN);

        if (authorization == null) {
            throw new EntityNotFoundException("Authorization not found. Please provide an existing access token");
        }
        authorizationService.remove(authorization);
    }

    @Override
    public void logoutAll() {
        String email = SessionUtil.getEmail();
        log.info("User email: {}", email);
        authorizationService.revokeAllByPrincipal(email);
    }
}
