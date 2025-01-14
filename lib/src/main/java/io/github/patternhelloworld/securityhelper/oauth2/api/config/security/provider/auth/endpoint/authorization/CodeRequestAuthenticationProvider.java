package io.github.patternhelloworld.securityhelper.oauth2.api.config.security.provider.auth.endpoint.authorization;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;

public final class CodeRequestAuthenticationProvider implements AuthenticationProvider {

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        authentication.setAuthenticated(true);
        return authentication;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2AuthorizationCodeRequestAuthenticationToken.class.isAssignableFrom(authentication);
    }

}
