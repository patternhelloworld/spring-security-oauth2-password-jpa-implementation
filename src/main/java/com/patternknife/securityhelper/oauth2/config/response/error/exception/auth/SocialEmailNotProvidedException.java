package com.patternknife.securityhelper.oauth2.config.response.error.exception.auth;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;


@ResponseStatus(value = HttpStatus.INTERNAL_SERVER_ERROR)
public class SocialEmailNotProvidedException extends RuntimeException {
    public SocialEmailNotProvidedException(String message) {
        super(message);
    }
}