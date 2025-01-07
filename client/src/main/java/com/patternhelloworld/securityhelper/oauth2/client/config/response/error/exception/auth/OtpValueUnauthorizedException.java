package com.patternhelloworld.securityhelper.oauth2.client.config.response.error.exception.auth;


import org.springframework.security.core.AuthenticationException;

public class OtpValueUnauthorizedException extends AuthenticationException {
    public OtpValueUnauthorizedException(String message) {
        super(message);
    }
}