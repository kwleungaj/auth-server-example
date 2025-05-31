package com.wingsofpear.authserverexample.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.wingsofpear.authserverexample.auth.OAuth.OtpAuthenticationConverter;
import com.wingsofpear.authserverexample.auth.OAuth.OtpAuthenticationProvider;
import com.wingsofpear.authserverexample.auth.dto.CustomUserDetails;
import com.wingsofpear.authserverexample.auth.service.CustomAuthorizationService;
import com.wingsofpear.authserverexample.auth.service.OtpService;
import com.wingsofpear.authserverexample.common.constant.AuthConstant;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.Resource;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.UUID;

@Configuration
public class AuthorizationServerConfig {

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(
            HttpSecurity http,
            OtpService otpService,
            UserDetailsService userDetailsService,
            OAuth2TokenGenerator<OAuth2Token> tokenGenerator,
            OAuth2AuthorizationService oAuth2AuthorizationService
    ) throws Exception {
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                OAuth2AuthorizationServerConfigurer.authorizationServer();
        RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();

        http
                .securityMatcher(endpointsMatcher)
                .with(authorizationServerConfigurer, (authorizationServer) ->
                        authorizationServer
//                                .oidc(Customizer.withDefaults())    // Enable OpenID Connect 1.0
                                .tokenEndpoint(tokenEndpoint -> tokenEndpoint
                                        .accessTokenRequestConverter(new OtpAuthenticationConverter())
                                        .authenticationProvider(new OtpAuthenticationProvider(
                                                otpService,
                                                userDetailsService,
                                                tokenGenerator,
                                                oAuth2AuthorizationService)
                                        )
                                )
                )
                .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated());

        return http.build();
    }

    /**
     * One option to use refresh token with public client (client with ClientAuthenticationMethod.NONE):
     * <a href="https://medium.com/@afeefrazickamir/spring-authorization-server-public-client-pkce-authorization-code-flow-with-refresh-tokens-ac2763080898">Refresh tokens for public client</a>
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository(
            JdbcOperations jdbcOperations,
            PasswordEncoder pwEncoder,
            @Value("${app.auth.jwt.access-token-validity-seconds}") long accessTokenDurationS,
            @Value("${app.auth.jwt.refresh-token-validity-seconds}") long refreshTokenDurationS
    ) {
        JdbcRegisteredClientRepository repo = new JdbcRegisteredClientRepository(jdbcOperations);
        // If you need to seed a first client on startup
        if (repo.findByClientId("mobile-client") == null) {
            RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId("mobile-client")
                    .clientSecret(pwEncoder.encode("secret")) // todo: store secret in secret
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                    .authorizationGrantType(new AuthorizationGrantType("otp"))
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .scope("read").scope("write")
//                .clientSettings(ClientSettings.builder()
//                        .requireAuthorizationConsent(true) // show an explicit “consent” (aka approval) screen to the end-user when they first authorize your application
//                        .requireProofKey(true) // PKCE
//                        .build())
                    .tokenSettings(TokenSettings.builder()
                            .accessTokenTimeToLive(Duration.ofSeconds(accessTokenDurationS))
                            .refreshTokenTimeToLive(Duration.ofSeconds(refreshTokenDurationS))
                            .reuseRefreshTokens(false) // rotate refresh tokens automatically
                            .build())
                    .build();
            repo.save(client);
        }
        return repo;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource(
            @Value("${app.auth.jwt.keystore}") Resource keystoreResource,
            @Value("${app.auth.jwt.keystore-password}") String keystorePassword,
            @Value("${app.auth.jwt.key-alias}") String keyAlias,
            @Value("${app.auth.jwt.key-password}") String keyPassword
    ) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {

        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (InputStream in = keystoreResource.getInputStream()) {
            ks.load(in, keystorePassword.toCharArray());
        }

        Key key = ks.getKey(keyAlias, keyPassword.toCharArray());
        if (!(key instanceof RSAPrivateKey privateKey)) {
            throw new IllegalStateException("Key under alias '" + keyAlias + "' is not an RSA private key");
        }

        RSAPublicKey publicKey = (RSAPublicKey) ks.getCertificate(keyAlias).getPublicKey();

        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(keyAlias)
                .build();

        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }

    /**
     * This is required for refresh token grant type. OAuth2RefreshTokenAuthenticationProvider needs to find
     * the OAuth2Authorization by the refresh token in order to do validation and setup token context for new tokens.
     */
    @Bean
    OAuth2AuthorizationService oAuth2AuthorizationService(JdbcOperations jdbcOperations, RegisteredClientRepository clientRepository) {
        JdbcOAuth2AuthorizationService jdbcOAuth2Service = new JdbcOAuth2AuthorizationService(jdbcOperations, clientRepository);
        jdbcOAuth2Service.setAuthorizationRowMapper(new CustomAuthorizationRowMapper(clientRepository));
        return new CustomAuthorizationService(jdbcOperations, jdbcOAuth2Service);
    }

    @Bean
    public OAuth2TokenGenerator<OAuth2Token> tokenGenerator(JWKSource<SecurityContext> jwkSource,
                                                            OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer) {
        JwtEncoder jwtEncoder = new NimbusJwtEncoder(jwkSource);
        JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
        jwtGenerator.setJwtCustomizer(jwtCustomizer);

        OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
        OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();

        return new DelegatingOAuth2TokenGenerator(jwtGenerator, accessTokenGenerator, refreshTokenGenerator);
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
        return context -> {
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                // what you set as the principal in your OtpAuthenticationProvider
                Authentication authPrincipal = context.getPrincipal(); // UsernamePasswordAuthenticationToken
                Object principal = authPrincipal.getPrincipal(); // CustomUserDetails
                if (principal instanceof CustomUserDetails user) {
                    context.getClaims().claim(AuthConstant.USER_ID, user.getId());
                }
            }
        };
    }

    static class CustomAuthorizationRowMapper extends JdbcOAuth2AuthorizationService.OAuth2AuthorizationRowMapper {
        CustomAuthorizationRowMapper(RegisteredClientRepository clients) {
            super(clients);
            getObjectMapper().addMixIn(
                    CustomUserDetails.class,
                    CustomUserDetailsMixin.class
            );
        }
    }

}
