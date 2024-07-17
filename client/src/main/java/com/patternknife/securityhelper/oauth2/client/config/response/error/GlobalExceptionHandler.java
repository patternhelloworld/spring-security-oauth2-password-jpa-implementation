package com.patternknife.securityhelper.oauth2.client.config.response.error;


import com.patternknife.securityhelper.oauth2.client.config.response.error.dto.CustomErrorResponsePayload;

import com.patternknife.securityhelper.oauth2.client.config.response.error.message.GeneralErrorMessage;
import io.github.patternknife.securityhelper.oauth2.api.config.response.error.ExceptionKnifeUtils;
import io.github.patternknife.securityhelper.oauth2.api.config.response.error.dto.ErrorResponsePayload;
import io.github.patternknife.securityhelper.oauth2.api.config.response.error.exception.auth.KnifeOauth2AuthenticationException;
import io.github.patternknife.securityhelper.oauth2.api.config.security.message.DefaultSecurityUserExceptionMessage;
import io.github.patternknife.securityhelper.oauth2.api.config.security.message.ISecurityUserExceptionMessageService;
import lombok.RequiredArgsConstructor;;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import org.springframework.web.context.request.WebRequest;


/*
 *
 *   Customize the exception payload by implementing this, which replaces
 *          'io.github.patternknife.securityhelper.oauth2.api.config.response.error.SecurityKnifeExceptionHandler'
 *
 *   Once you create 'GlobalExceptionHandler', you should insert the following two as default. Otherwise, 'unhandledExceptionHandler' is prior to 'io.github.patternknife.securityhelper.oauth2.api.config.response.error.SecurityKnifeExceptionHandler'.
 *
 * */
@ControllerAdvice
@RequiredArgsConstructor
public class GlobalExceptionHandler {

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

    // 403 : Authorization
    @ExceptionHandler({ AccessDeniedException.class })
    public ResponseEntity<?> authorizationException(Exception ex, WebRequest request) {
        ErrorResponsePayload errorResponsePayload = new ErrorResponsePayload(ex.getMessage() != null ? ex.getMessage() : ExceptionKnifeUtils.getAllCauses(ex), request.getDescription(false),
                ex.getMessage() == null || ex.getMessage().equals("Access Denied") ? iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHORIZATION_FAILURE) : ex.getMessage(), ex.getStackTrace()[0].toString());
        return new ResponseEntity<>(errorResponsePayload, HttpStatus.FORBIDDEN);
    }

    // Unhandled
    @ExceptionHandler(Exception.class)
    public ResponseEntity<?> unhandledExceptionHandler(Exception ex, WebRequest request) {
        CustomErrorResponsePayload customErrorResponsePayload = new CustomErrorResponsePayload(ex.getMessage(), request.getDescription(false), GeneralErrorMessage.UNHANDLED_ERROR.getUserMessage(),
                CustomExceptionUtils.getAllStackTraces(ex), CustomExceptionUtils.getAllCauses(ex));
        return new ResponseEntity<>(customErrorResponsePayload, HttpStatus.INTERNAL_SERVER_ERROR);
    }

}
