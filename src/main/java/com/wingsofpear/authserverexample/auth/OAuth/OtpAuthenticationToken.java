package com.wingsofpear.authserverexample.auth.OAuth;

import lombok.Getter;
import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

@Getter
public class OtpAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {
    public static final AuthorizationGrantType grantType = new AuthorizationGrantType("otp");
    private final String email;
    private final String otp;
    private final Set<String> scopes;

    public OtpAuthenticationToken(
            String email,
            String otp,
            Authentication clientPrincipal,
            @Nullable Set<String> scopes,
            @Nullable Map<String,Object> additionalParameters
    ) {
        super(grantType, clientPrincipal, additionalParameters);
        Assert.hasText(email, "email cannot be empty");
        Assert.hasText(otp, "otp cannot be empty");
        this.email = email;
        this.otp   = otp;
        this.scopes = Collections.unmodifiableSet((Set)(scopes != null ? new HashSet(scopes) : Collections.emptySet()));
    }

}
