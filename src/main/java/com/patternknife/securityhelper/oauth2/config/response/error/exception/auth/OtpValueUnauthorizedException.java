package com.patternknife.securityhelper.oauth2.config.response.error.exception.auth;


import org.springframework.security.core.AuthenticationException;

public class OtpValueUnauthorizedException extends AuthenticationException {
    public OtpValueUnauthorizedException(String message) {
        super(message);
    }
}