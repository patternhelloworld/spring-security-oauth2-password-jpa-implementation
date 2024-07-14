package com.patternknife.securityhelper.oauth2.client.config.response.error.exception.auth;

public class AlreadySocialRegisteredException extends RuntimeException {
    public AlreadySocialRegisteredException(String message) {
        super(message);
    }
}