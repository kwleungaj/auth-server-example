package com.wingsofpear.authserverexample.common.audit;

import com.wingsofpear.authserverexample.common.constant.SystemConstants;
import com.wingsofpear.authserverexample.common.util.SessionUtil;
import org.springframework.data.domain.AuditorAware;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Optional;

public class AuditorAwareImpl implements AuditorAware<Long> {
    @Override
    public Optional<Long> getCurrentAuditor() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated() || auth instanceof AnonymousAuthenticationToken) {
            return Optional.of(SystemConstants.SYSTEM_USER_ID);
        }
        Long userId = SessionUtil.getUserId();
        return Optional.of(userId);
    }
}
