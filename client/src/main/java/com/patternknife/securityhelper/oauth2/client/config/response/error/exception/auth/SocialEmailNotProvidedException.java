package com.patternknife.securityhelper.oauth2.client.config.response.error.exception.auth;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;


@ResponseStatus(value = HttpStatus.UNAUTHORIZED)
public class SocialEmailNotProvidedException extends RuntimeException {
    public SocialEmailNotProvidedException(String message) {
        super(message);
    }
}