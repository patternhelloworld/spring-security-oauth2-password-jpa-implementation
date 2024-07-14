package com.patternknife.securityhelper.oauth2.client.config.response.error.exception.auth;

import org.springframework.security.access.AccessDeniedException;

public class CustomAuthGuardException extends AccessDeniedException {

    public CustomAuthGuardException(String message) {
        super(message);
    }
}