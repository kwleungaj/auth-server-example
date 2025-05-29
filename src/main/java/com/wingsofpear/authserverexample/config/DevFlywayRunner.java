package com.wingsofpear.authserverexample.config;

import org.flywaydb.core.Flyway;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.UUID;

@Component
@Profile("dev")
public class DevFlywayRunner implements ApplicationRunner {

    private final Flyway flyway;
    private final JdbcRegisteredClientRepository registeredClientRepository;
    private final PasswordEncoder pwEncoder;
    private final long accessTokenDurationS;
    private final long refreshTokenDurationS;

    public DevFlywayRunner(Flyway flyway,
                           JdbcRegisteredClientRepository registeredClientRepository,
                           PasswordEncoder pwEncoder,
                           @Value("${app.auth.jwt.access-token-validity-seconds}") long accessTokenDurationS,
                           @Value("${app.auth.jwt.refresh-token-validity-seconds}") long refreshTokenDurationS
    ) {
        this.flyway = flyway;
        this.registeredClientRepository = registeredClientRepository;
        this.pwEncoder = pwEncoder;
        this.accessTokenDurationS = accessTokenDurationS;
        this.refreshTokenDurationS = refreshTokenDurationS;
    }

    @Override
    public void run(ApplicationArguments args) throws Exception {
        flyway.clean();
        flyway.migrate();
        addClient(registeredClientRepository, pwEncoder, accessTokenDurationS, refreshTokenDurationS);
    }


    private void addClient(JdbcRegisteredClientRepository repo,
                           PasswordEncoder pwEncoder,
                           long accessTokenDurationS,
                           @Value("${app.auth.jwt.refresh-token-validity-seconds}") long refreshTokenDurationS
    ) {
        if (repo.findByClientId("mobile-client") == null) {
            RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId("mobile-client")
                    .clientSecret(pwEncoder.encode("secret"))
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                    .authorizationGrantType(new AuthorizationGrantType("otp"))
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .scope("read").scope("write")
                    .tokenSettings(TokenSettings.builder()
                            .accessTokenTimeToLive(Duration.ofSeconds(accessTokenDurationS))
                            .refreshTokenTimeToLive(Duration.ofSeconds(refreshTokenDurationS))
                            .reuseRefreshTokens(false) // rotate refresh tokens automatically
                            .build())
                    .build();
            repo.save(client);

        }
    }
}
