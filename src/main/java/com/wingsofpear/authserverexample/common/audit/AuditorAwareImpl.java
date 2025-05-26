package com.wingsofpear.authserverexample.common.audit;

import com.wingsofpear.authserverexample.auth.dto.CustomUserDetails;
import com.wingsofpear.authserverexample.common.constant.SystemConstants;
import org.springframework.data.domain.AuditorAware;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import java.util.Optional;

// todo: replace var and check the use of instanceof
public class AuditorAwareImpl implements AuditorAware<Long> {
    @Override
    public Optional<Long> getCurrentAuditor() {
        var auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()) {
            return Optional.of(SystemConstants.SYSTEM_USER_ID);
        }
        var principal = auth.getPrincipal();
        if (principal instanceof UserDetails ud) {
            // cast your UserDetails to get user ID
            return Optional.of(((CustomUserDetails) ud).getId());
        }
        return Optional.of(SystemConstants.SYSTEM_USER_ID);
    }
}
