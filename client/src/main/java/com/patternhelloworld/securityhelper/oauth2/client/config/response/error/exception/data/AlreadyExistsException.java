package com.patternhelloworld.securityhelper.oauth2.client.config.response.error.exception.data;

public class AlreadyExistsException extends RuntimeException {
    public AlreadyExistsException(String message) {
        super(message);
    }
    public AlreadyExistsException(String message, Throwable cause) {
        super(message, cause);
    }
}
