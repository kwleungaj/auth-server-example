package com.wingsofpear.authserverexample.auth.service;

import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;

/**
 * Add revokeAllByPrincipal() on top of OAuth2AuthorizationService methods
 */
public class CustomAuthorizationService implements OAuth2AuthorizationService {

    private final OAuth2AuthorizationService delegate;
    private final JdbcOperations jdbcOps;

    public CustomAuthorizationService(JdbcOperations jdbcOps,
                                      OAuth2AuthorizationService oAuth2AuthorizationService) {
        this.jdbcOps = jdbcOps;
        this.delegate = oAuth2AuthorizationService;
    }

    @Override
    public void save(OAuth2Authorization auth) {
        delegate.save(auth);
    }

    @Override
    public void remove(OAuth2Authorization auth) {
        delegate.remove(auth);
    }

    @Override
    public OAuth2Authorization findById(String id) {
        return delegate.findById(id);
    }

    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        return delegate.findByToken(token, tokenType);
    }

    public void revokeAllByPrincipal(String principalName) {
        jdbcOps.update("DELETE FROM oauth2_authorization WHERE principal_name = ?", principalName);
    }
}
