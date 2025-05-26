package com.wingsofpear.authserverexample.config;

import org.flywaydb.core.Flyway;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

@Component
@Profile("dev")
public class DevFlywayRunner implements ApplicationRunner {

    private final Flyway flyway;

    public DevFlywayRunner(Flyway flyway) {
        this.flyway = flyway;
    }

    @Override
    public void run(ApplicationArguments args) throws Exception {
        flyway.clean();
        flyway.migrate();
    }
}
