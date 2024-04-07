package com.patternknife.securityhelper.oauth2.config.response.error.exception.auth;


public class OtpValueUnauthorizedException extends RuntimeException {
    public OtpValueUnauthorizedException(String message) {
        super(message);
    }
}