package com.wingsofpear.authserverexample.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.DefaultUriBuilderFactory;

import java.util.List;

@Configuration
public class RestTemplateConfiguration {
    @Value("${app.auth.base-url}")
    private String authServerBaseUrl;

    @Bean
    public RestTemplate oauth2RestTemplate() {
        RestTemplate restTemplate = new RestTemplate();
        DefaultUriBuilderFactory uriFactory = new DefaultUriBuilderFactory(authServerBaseUrl);
        restTemplate.setUriTemplateHandler(uriFactory);
        restTemplate.setMessageConverters(List.of(
                new FormHttpMessageConverter(),
                new OAuth2AccessTokenResponseHttpMessageConverter(),
                new MappingJackson2HttpMessageConverter()
        ));

        return restTemplate;
    }

}
