package io.github.patternknife.securityhelper.oauth2.api.config.security.response.error.handler;


import io.github.patternknife.securityhelper.oauth2.api.config.security.response.error.dto.ErrorResponsePayload;

import io.github.patternknife.securityhelper.oauth2.api.config.security.message.DefaultSecurityUserExceptionMessage;

import io.github.patternknife.securityhelper.oauth2.api.config.security.message.ISecurityUserExceptionMessageService;
import io.github.patternknife.securityhelper.oauth2.api.config.security.response.error.exception.KnifeOauth2AuthenticationException;
import io.github.patternknife.securityhelper.oauth2.api.config.security.response.error.util.ExceptionKnifeUtils;

import io.github.patternknife.securityhelper.oauth2.api.config.security.util.OrderConstants;
import lombok.RequiredArgsConstructor;

import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import org.springframework.web.context.request.WebRequest;

@Order(OrderConstants.SECURITY_KNIFE_EXCEPTION_HANDLER_ORDER)
@ControllerAdvice
@RequiredArgsConstructor
public class SecurityKnifeExceptionHandler {

    private final ISecurityUserExceptionMessageService iSecurityUserExceptionMessageService;

    // 401 : Authentication
    @ExceptionHandler({AuthenticationException.class})
    public ResponseEntity<?> authenticationException(Exception ex, WebRequest request) {
        ErrorResponsePayload errorResponsePayload;
        if(ex instanceof KnifeOauth2AuthenticationException && ((KnifeOauth2AuthenticationException) ex).getErrorMessages() != null) {
            errorResponsePayload = new ErrorResponsePayload(((KnifeOauth2AuthenticationException) ex).getErrorMessages(),
                    ex, request.getDescription(false), ExceptionKnifeUtils.getAllStackTraces(ex),
                    ExceptionKnifeUtils.getAllCauses(ex), null);
        }else {
            errorResponsePayload = new ErrorResponsePayload(ExceptionKnifeUtils.getAllCauses(ex), request.getDescription(false), iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_LOGIN_FAILURE),
                    ex.getMessage(), ex.getStackTrace()[0].toString());
        }
        return new ResponseEntity<>(errorResponsePayload, HttpStatus.UNAUTHORIZED);
    }

    // 403 : Authorization (= Forbidden, AccessDenied)
    @ExceptionHandler({ AccessDeniedException.class })
    public ResponseEntity<?> authorizationException(Exception ex, WebRequest request) {
        ErrorResponsePayload errorResponsePayload = new ErrorResponsePayload(ex.getMessage() != null ? ex.getMessage() : ExceptionKnifeUtils.getAllCauses(ex), request.getDescription(false),
                ex.getMessage() == null || ex.getMessage().equals("Access Denied") ? iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHORIZATION_FAILURE) : ex.getMessage(), ex.getStackTrace()[0].toString());
        return new ResponseEntity<>(errorResponsePayload, HttpStatus.FORBIDDEN);
    }

}
