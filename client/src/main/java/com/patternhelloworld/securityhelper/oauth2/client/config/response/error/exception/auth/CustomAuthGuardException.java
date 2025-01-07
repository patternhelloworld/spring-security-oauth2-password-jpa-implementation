package com.patternhelloworld.securityhelper.oauth2.client.config.response.error.exception.auth;

import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.response.error.exception.EasyPlusOauth2AuthorizationException;

public class CustomAuthGuardException extends EasyPlusOauth2AuthorizationException {

    public CustomAuthGuardException(String message) {
        super(message);
    }
}