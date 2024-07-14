package com.patternknife.securityhelper.oauth2.api.config.response.error.exception.auth;


import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(value = HttpStatus.FORBIDDEN)
public class KnifeOauth2AuthorizationException extends AccessDeniedException {
    public KnifeOauth2AuthorizationException(String message) {
        super(message);
    }
    public KnifeOauth2AuthorizationException() {
        super(null);
    }
}