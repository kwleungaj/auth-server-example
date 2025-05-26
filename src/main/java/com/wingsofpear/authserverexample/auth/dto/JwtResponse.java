package com.wingsofpear.authserverexample.auth.dto;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import lombok.AllArgsConstructor;
import lombok.Data;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;

import java.time.Instant;

@Data
@AllArgsConstructor
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class JwtResponse {
    private String accessToken;
    private String refreshToken;
    private Instant expiresAt;
    private String tokenType;

    public JwtResponse(OAuth2AccessTokenResponse response) {
        this.accessToken = response.getAccessToken().getTokenValue();
        assert response.getRefreshToken() != null;
        this.refreshToken = response.getRefreshToken().getTokenValue();
        this.expiresAt = response.getAccessToken().getExpiresAt();
        this.tokenType = response.getAccessToken().getTokenType().getValue();
    }
}
