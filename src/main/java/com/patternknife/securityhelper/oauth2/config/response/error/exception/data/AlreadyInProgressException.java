package com.patternknife.securityhelper.oauth2.config.response.error.exception.data;


public class AlreadyInProgressException extends RuntimeException {
    public AlreadyInProgressException(String message) {
        super(message);
    }
}
