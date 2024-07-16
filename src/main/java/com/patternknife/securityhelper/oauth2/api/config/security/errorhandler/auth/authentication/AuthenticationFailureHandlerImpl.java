package com.patternknife.securityhelper.oauth2.api.config.security.errorhandler.auth.authentication;


import com.patternknife.securityhelper.oauth2.api.config.logger.module.CustomSecurityLogConfig;
import com.patternknife.securityhelper.oauth2.api.config.response.error.dto.ErrorResponsePayload;
import com.patternknife.securityhelper.oauth2.api.config.response.error.exception.auth.KnifeOauth2AuthenticationException;
import com.patternknife.securityhelper.oauth2.api.config.response.error.message.SecurityUserExceptionMessage;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.patternknife.securityhelper.oauth2.api.config.response.error.CustomExceptionUtils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import java.io.IOException;


public class AuthenticationFailureHandlerImpl implements AuthenticationFailureHandler {

    private static final Logger logger = LoggerFactory.getLogger(CustomSecurityLogConfig.class);

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception)
            throws IOException {

        ErrorResponsePayload errorResponsePayload;
        String stackTraces = CustomExceptionUtils.getAllStackTraces(exception);
        if(exception instanceof KnifeOauth2AuthenticationException){
            errorResponsePayload = new ErrorResponsePayload(((KnifeOauth2AuthenticationException) exception).getErrorMessages().getMessage(),
                    "uri=" + request.getRequestURI(), ((KnifeOauth2AuthenticationException) exception).getErrorMessages().getUserMessage(), stackTraces);
        }else if(exception instanceof OAuth2AuthenticationException) {
            errorResponsePayload = new ErrorResponsePayload(
                    ((OAuth2AuthenticationException) exception).getError().getErrorCode() + " / " + ((OAuth2AuthenticationException) exception).getError().getDescription(),
                    "uri=" + request.getRequestURI(),
                    SecurityUserExceptionMessage.AUTHENTICATION_LOGIN_FAILURE.getMessage(),
                    stackTraces);
        }else{
            errorResponsePayload = new ErrorResponsePayload(
                    exception.getMessage(),
                    "uri=" + request.getRequestURI(),
                    SecurityUserExceptionMessage.AUTHENTICATION_LOGIN_ERROR.getMessage(),
                    stackTraces);
        }

        // Set response status
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        // Write the error details to the response
        response.getWriter().write(new ObjectMapper().writeValueAsString(errorResponsePayload));

        logger.warn(new String(errorResponsePayload.toString().getBytes(), "UTF-8"));

    }
}
