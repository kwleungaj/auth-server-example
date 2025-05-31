package com.wingsofpear.authserverexample.auth.client;

import com.wingsofpear.authserverexample.common.constant.AuthConstant;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

@Component
@Slf4j
public class AuthClient {
    private final RestTemplate restTemplate;
    private final String clientId = "mobile-client";
    private final String clientSecret = "secret";  // todo: move secret to secret
    private final String scope = "read write";

    public AuthClient(@Qualifier("oauth2RestTemplate") RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public OAuth2AccessTokenResponse loginWithOtp(String email, String otp) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add(OAuth2ParameterNames.GRANT_TYPE, AuthConstant.OTP);
        form.add(AuthConstant.EMAIL, email);
        form.add(AuthConstant.OTP, otp);
        return postAuthTokenRequest(form);
    }

    public OAuth2AccessTokenResponse refreshToken(String refreshToken) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add(OAuth2ParameterNames.GRANT_TYPE, OAuth2ParameterNames.REFRESH_TOKEN);
        form.add(OAuth2ParameterNames.REFRESH_TOKEN, refreshToken);
        return postAuthTokenRequest(form);
    }

    private OAuth2AccessTokenResponse postAuthTokenRequest(MultiValueMap<String, String> form) {
        form.add(OAuth2ParameterNames.CLIENT_ID, clientId);
        form.add(OAuth2ParameterNames.CLIENT_SECRET, clientSecret);
        form.add(OAuth2ParameterNames.SCOPE, scope);

        String url = "/oauth2/token";
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        HttpEntity<MultiValueMap<String, String>> tokenReq = new HttpEntity<>(form, headers);
        OAuth2AccessTokenResponse response = null;

        try {
            ResponseEntity<OAuth2AccessTokenResponse> tokenResp = restTemplate
                    .postForEntity(url, tokenReq, OAuth2AccessTokenResponse.class);
            response = tokenResp.getBody();
        } catch (Exception e) {
            log.info("Authentication Error: {}", e.getMessage());
            throw new OAuth2AuthenticationException(new OAuth2Error("Server Error"));
        }

        if (response == null) {
            throw new OAuth2AuthenticationException(new OAuth2Error("Server Error"));
        }

        return response;
    }

    public void postRevokeTokenRequest(String refreshToken) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add(OAuth2ParameterNames.TOKEN, refreshToken);
        form.add(OAuth2ParameterNames.TOKEN_TYPE_HINT, OAuth2ParameterNames.REFRESH_TOKEN);
        form.add(OAuth2ParameterNames.CLIENT_ID, clientId);
        form.add(OAuth2ParameterNames.CLIENT_SECRET, clientSecret);

        String url = "/oauth2/revoke";
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        HttpEntity<MultiValueMap<String, String>> tokenReq = new HttpEntity<>(form, headers);

        restTemplate.postForEntity(url, tokenReq, Void.class);
    }

}
