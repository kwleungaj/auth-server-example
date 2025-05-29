package com.wingsofpear.authserverexample.auth.OAuth;


import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.core.Authentication;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import java.util.*;

import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.GRANT_TYPE;

public class OtpAuthenticationConverter implements AuthenticationConverter {

    @Override
    public Authentication convert(HttpServletRequest request) {
        MultiValueMap<String, String> parameters = getFormParameters(request);

        String grantType = parameters.getFirst(GRANT_TYPE);
        if (!OtpAuthenticationToken.grantType.getValue().equals(grantType)) {
            return null;
        }

        Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();

        String email = parameters.getFirst("email");
        String otp   = parameters.getFirst("otp");
        if (email == null || otp == null) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, "Missing email or otp", null)
            );
        }
//        Map<String,Object> params = new HashMap<>();
//        params.put("email", request.getParameter("email"));
//        params.put("otp", request.getParameter("otp"));
//        params.put(OAuth2ParameterNames.SCOPE, request.getParameter(OAuth2ParameterNames.SCOPE));

        // scopes
        String scope = parameters.getFirst("scope");
        if (StringUtils.hasText(scope) && (parameters.get("scope")).size() != 1) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, "Too many scope parameter", null)
            );
        }

        Set<String> requestedScopes = null;
        if (StringUtils.hasText(scope)) {
            requestedScopes = new HashSet<>(Arrays.asList(StringUtils.delimitedListToStringArray(scope, " ")));
        }

        // additional parameters
        Map<String, Object> additionalParameters = new HashMap<>();
        parameters.forEach((key, value) -> {
            if (!key.equals("grant_type") && !key.equals("email") && !key.equals("otp") && !key.equals("scope")) {
                additionalParameters.put(key, value.size() == 1 ? value.getFirst() : value.toArray(new String[0]));
            }

        });

        return new OtpAuthenticationToken(email, otp, clientPrincipal, requestedScopes, additionalParameters);
    }

    static MultiValueMap<String, String> getFormParameters(HttpServletRequest request) {
        Map<String, String[]> parameterMap = request.getParameterMap();
        MultiValueMap<String, String> parameters = new LinkedMultiValueMap();
        parameterMap.forEach((key, values) -> {
            String queryString = StringUtils.hasText(request.getQueryString()) ? request.getQueryString() : "";
            if (!queryString.contains(key) && values.length > 0) {
                for(String value : values) {
                    parameters.add(key, value);
                }
            }

        });
        return parameters;
    }

    static MultiValueMap<String, String> getQueryParameters(HttpServletRequest request) {
        Map<String, String[]> parameterMap = request.getParameterMap();
        MultiValueMap<String, String> parameters = new LinkedMultiValueMap();
        parameterMap.forEach((key, values) -> {
            String queryString = StringUtils.hasText(request.getQueryString()) ? request.getQueryString() : "";
            if (queryString.contains(key) && values.length > 0) {
                for(String value : values) {
                    parameters.add(key, value);
                }
            }

        });
        return parameters;
    }
}
