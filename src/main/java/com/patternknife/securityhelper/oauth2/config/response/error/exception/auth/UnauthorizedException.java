package com.patternknife.securityhelper.oauth2.config.response.error.exception.auth;


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