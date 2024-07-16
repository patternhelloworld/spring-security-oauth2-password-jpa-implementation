package io.github.patternknife.securityhelper.oauth2.api.config.response.error;


import io.github.patternknife.securityhelper.oauth2.api.config.response.error.dto.ErrorResponsePayload;
import io.github.patternknife.securityhelper.oauth2.api.config.response.error.exception.auth.*;

import io.github.patternknife.securityhelper.oauth2.api.config.security.message.DefaultSecurityUserExceptionMessage;

import io.github.patternknife.securityhelper.oauth2.api.config.security.message.ISecurityUserExceptionMessageService;
import io.github.patternknife.securityhelper.oauth2.api.config.response.error.exception.auth.KnifeOauth2AuthenticationException;
import lombok.RequiredArgsConstructor;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import org.springframework.web.context.request.WebRequest;

@Order(Ordered.HIGHEST_PRECEDENCE)
@ControllerAdvice
@RequiredArgsConstructor
public class SecurityGlobalExceptionHandler {

    private final ISecurityUserExceptionMessageService iSecurityUserExceptionMessageService;

    // 401 : Authentication
    @ExceptionHandler({AuthenticationException.class})
    public ResponseEntity<?> authenticationException(Exception ex, WebRequest request) {
        ErrorResponsePayload errorResponsePayload;
        if(ex instanceof KnifeOauth2AuthenticationException && ((KnifeOauth2AuthenticationException) ex).getErrorMessages() != null) {
            errorResponsePayload = new ErrorResponsePayload(((KnifeOauth2AuthenticationException) ex).getErrorMessages(),
                    ex, request.getDescription(false), CustomExceptionUtils.getAllStackTraces(ex),
                    CustomExceptionUtils.getAllCauses(ex), null);
        }else {
            errorResponsePayload = new ErrorResponsePayload(CustomExceptionUtils.getAllCauses(ex), request.getDescription(false), iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_LOGIN_FAILURE),
                    ex.getMessage(), ex.getStackTrace()[0].toString());
        }
        return new ResponseEntity<>(errorResponsePayload, HttpStatus.UNAUTHORIZED);
    }

    // 403 : Authorization
    @ExceptionHandler({ AccessDeniedException.class })
    public ResponseEntity<?> authorizationException(Exception ex, WebRequest request) {
        ErrorResponsePayload errorResponsePayload = new ErrorResponsePayload(ex.getMessage() != null ? ex.getMessage() : CustomExceptionUtils.getAllCauses(ex), request.getDescription(false),
                ex.getMessage() == null || ex.getMessage().equals("Access Denied") ? iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHORIZATION_FAILURE) : ex.getMessage(), ex.getStackTrace()[0].toString());
        return new ResponseEntity<>(errorResponsePayload, HttpStatus.FORBIDDEN);
    }
}
