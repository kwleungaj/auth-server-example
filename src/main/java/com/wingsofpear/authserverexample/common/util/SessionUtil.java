package com.wingsofpear.authserverexample.common.util;

import com.wingsofpear.authserverexample.common.constant.AuthConstant;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;

import java.util.Collection;
import java.util.Optional;

public class SessionUtil {
    public static Optional<Jwt> getJwt() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getPrincipal() instanceof Jwt jwt) {
            return Optional.of(jwt);
        }
        return Optional.empty();
    }

    public static Jwt getJwtOrThrow() {
        return getJwt().orElseThrow(() -> new BadCredentialsException("Jwt not found"));
    }

    public static String getAccessToken() {
        return getJwtOrThrow().getTokenValue();
    }

    public static Long getUserId() {
        return getJwtOrThrow().getClaim(AuthConstant.USER_ID);
    }

    public static String getEmail() {
        return getJwtOrThrow().getClaim(AuthConstant.SUBJECT);
    }

    public static Collection<? extends GrantedAuthority> getAuthorities() {
        return new JwtGrantedAuthoritiesConverter().convert(getJwtOrThrow());
    }
}
