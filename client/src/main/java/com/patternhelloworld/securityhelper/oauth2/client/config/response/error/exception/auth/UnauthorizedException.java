package com.patternhelloworld.securityhelper.oauth2.client.config.response.error.exception.auth;


import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(value = HttpStatus.FORBIDDEN)
public class UnauthorizedException extends AccessDeniedException {
    public UnauthorizedException(String message) {
        super(message);
    }
    public UnauthorizedException() {
        super(null);
    }
}