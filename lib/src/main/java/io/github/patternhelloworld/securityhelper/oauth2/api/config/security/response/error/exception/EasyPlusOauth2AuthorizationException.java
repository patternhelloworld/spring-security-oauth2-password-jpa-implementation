package io.github.patternhelloworld.securityhelper.oauth2.api.config.security.response.error.exception;


import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(value = HttpStatus.FORBIDDEN)
public class EasyPlusOauth2AuthorizationException extends AccessDeniedException {
    public EasyPlusOauth2AuthorizationException(String message) {
        super(message);
    }
    public EasyPlusOauth2AuthorizationException() {
        super(null);
    }
}