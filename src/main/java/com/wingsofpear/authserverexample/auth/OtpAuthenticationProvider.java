package com.wingsofpear.authserverexample.auth;

import com.wingsofpear.authserverexample.auth.service.OtpService;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.util.Assert;

import java.security.Principal;
import java.util.Set;

/**
 * Reference:
 * <li><a href="https://www.youtube.com/watch?v=HdSktctSplc">Spring Authorization Server 1.1.3 - Custom Password Grant Type</a></li>
 * <li><a href="https://glenmazza.net/blog/entry/spring-auth-server-custom-grant"> Adding a custom grant type to Spring Authorization Server </a></li>
 * <p>
 * We can use OAuth2AuthorizationService to store OAuth2Authorization (made up of tokens, grant type,
 * principal name, etc.) and configure to use InMemoryOAuth2AuthorizationService or
 * JdbcOAuth2AuthorizationService (point to a DataSource) for storage.
 * <p>
 * When to skip the database: Stateless APIs with JWTs and no revocation.
 * If you configure your authorization server to issue signed JWT access tokens and you never need to revoke them
 * before their natural expiry, you technically don’t need to store them.
 */
public class OtpAuthenticationProvider implements AuthenticationProvider {

    private final OtpService otpService;
    private final UserDetailsService userDetailsService;
    private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;
    private final OAuth2AuthorizationService authorizationService;

    public OtpAuthenticationProvider(OtpService otpService,
                                     UserDetailsService userDetailsService,
                                     OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator,
                                     OAuth2AuthorizationService authorizationService) {
        Assert.notNull(authorizationService, "otpService cannot be null");
        Assert.notNull(tokenGenerator, "userDetailsService cannot be null");
        Assert.notNull(tokenGenerator, "tokenGenerator cannot be null");
        Assert.notNull(authorizationService, "authorizationService cannot be null");
        this.otpService = otpService;
        this.userDetailsService = userDetailsService;
        this.tokenGenerator = tokenGenerator;
        this.authorizationService = authorizationService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        OtpAuthenticationToken otpToken = (OtpAuthenticationToken) authentication;
        // clientPrincipal of is authenticated by ClientSecretAuthenticationProvider even before triggering the OtpAuthenticationConverter
        OAuth2ClientAuthenticationToken clientPrincipal = (OAuth2ClientAuthenticationToken) otpToken.getPrincipal();
        RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();
        UserDetails user;
        Set<String> authorizedScopes = otpToken.getScopes();

        if (registeredClient == null) {
            throw new OAuth2AuthenticationException(new OAuth2Error(
                    OAuth2ErrorCodes.INVALID_CLIENT, "RegisteredClient is null.", null)
            );
        }

        if (!registeredClient.getAuthorizationGrantTypes().contains(otpToken.getGrantType())) {
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT));
        }

        user = userDetailsService.loadUserByUsername(otpToken.getEmail());

        if (!otpService.validateOtp(otpToken.getEmail(), otpToken.getOtp())) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT, "Invalid OTP", null)
            );
        } else {
            otpService.clearOtp(otpToken.getEmail());
        }

        UsernamePasswordAuthenticationToken principal =
                new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());

        // Generate access & refresh tokens
        DefaultOAuth2TokenContext.Builder tokenContextBuilder =
                DefaultOAuth2TokenContext.builder()
                        .registeredClient(registeredClient)
                        .principal(principal)
                        .authorizationServerContext(AuthorizationServerContextHolder.getContext())
                        .authorizedScopes(authorizedScopes)
                        .authorizationGrantType(otpToken.getGrantType())
                        .authorizationGrant(otpToken);

        OAuth2AccessToken accessToken = generateAccessToken(tokenContextBuilder);

        OAuth2RefreshToken refreshToken = registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN)
                ? generateRefreshToken(tokenContextBuilder)
                : null;

        OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(registeredClient)
                .principalName(principal.getName()) // this returns userDetails.getUsername() from AbstractAuthenticationToken class;
                .authorizationGrantType(otpToken.getGrantType())
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .authorizedScopes(authorizedScopes)
                .attribute(Principal.class.getName(), principal)    // must be provided for refresh token grant type to
                                                                    // get the principal to construct the
                                                                    // DefaultOAuth2TokenContext.Builder which is used
                                                                    // for generating access token and refresh token.
                .build();
        authorizationService.save(authorization);

        return new OAuth2AccessTokenAuthenticationToken(registeredClient, principal, accessToken, refreshToken);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OtpAuthenticationToken.class.isAssignableFrom(authentication);
    }

    private OAuth2AccessToken generateAccessToken(DefaultOAuth2TokenContext.Builder tokenContextBuilder) {
        OAuth2TokenContext tokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.ACCESS_TOKEN).build();
        // generatedAccessToken is of type Jwt which extends AbstractOAuth2Token class
        OAuth2Token generatedAccessToken = tokenGenerator.generate(tokenContext);

        if (generatedAccessToken == null) {
            throw new OAuth2AuthenticationException(new OAuth2Error(
                    OAuth2ErrorCodes.SERVER_ERROR,
                    "The token generator failed to generate access token",
                    null)
            );
        }
        return new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                generatedAccessToken.getTokenValue(),
                generatedAccessToken.getIssuedAt(),
                generatedAccessToken.getExpiresAt(),
                null);
    }

    private OAuth2RefreshToken generateRefreshToken(DefaultOAuth2TokenContext.Builder tokenContextBuilder) {
        OAuth2TokenContext tokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.REFRESH_TOKEN).build();
        OAuth2Token generatedRefreshToken = tokenGenerator.generate(tokenContext);

        if (!(generatedRefreshToken instanceof OAuth2RefreshToken)) {
            throw new OAuth2AuthenticationException(new OAuth2Error(
                    OAuth2ErrorCodes.SERVER_ERROR,
                    "The token generator failed to generate refresh token",
                    null)
            );
        }

        return (OAuth2RefreshToken) generatedRefreshToken;
    }
}
