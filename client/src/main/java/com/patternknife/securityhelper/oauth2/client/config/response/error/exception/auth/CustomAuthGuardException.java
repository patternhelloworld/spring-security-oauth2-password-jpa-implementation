package com.patternknife.securityhelper.oauth2.client.config.response.error.exception.auth;

import io.github.patternknife.securityhelper.oauth2.api.config.security.response.error.exception.KnifeOauth2AuthorizationException;

public class CustomAuthGuardException extends KnifeOauth2AuthorizationException {

    public CustomAuthGuardException(String message) {
        super(message);
    }
}