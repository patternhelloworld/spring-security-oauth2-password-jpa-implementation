package com.patternknife.securityhelper.oauth2.client.config.securityimpl.response;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.patternknife.securityhelper.oauth2.api.config.logger.KnifeSecurityLogConfig;
import io.github.patternknife.securityhelper.oauth2.api.config.security.message.DefaultSecurityUserExceptionMessage;
import io.github.patternknife.securityhelper.oauth2.api.config.security.message.ISecurityUserExceptionMessageService;
import io.github.patternknife.securityhelper.oauth2.api.config.security.response.error.dto.SecurityKnifeErrorResponsePayload;
import io.github.patternknife.securityhelper.oauth2.api.config.security.response.error.exception.KnifeOauth2AuthenticationException;
import io.github.patternknife.securityhelper.oauth2.api.config.security.response.error.util.ExceptionKnifeUtils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import java.io.IOException;


/*
 *
 * The functionality is already implemented in the library's
 * 'io.github.patternknife.securityhelper.oauth2.api.config.security.response.auth.authentication.DefaultAuthenticationFailureHandlerImpl'.
 *
 * Create this class only if you need a custom implementation that differs from the default.
 */
@Primary
@Qualifier("apiAuthenticationFailureHandler")
@Configuration
@RequiredArgsConstructor
public class CustomApiAuthenticationFailureHandlerImpl implements AuthenticationFailureHandler {

    private static final Logger logger = LoggerFactory.getLogger(KnifeSecurityLogConfig.class);

    private final ISecurityUserExceptionMessageService iSecurityUserExceptionMessageService;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception)
            throws IOException {

        SecurityKnifeErrorResponsePayload errorResponsePayload;
        String stackTraces = ExceptionKnifeUtils.getAllStackTraces(exception);
        if(exception instanceof KnifeOauth2AuthenticationException){
            errorResponsePayload = new SecurityKnifeErrorResponsePayload(((KnifeOauth2AuthenticationException) exception).getErrorMessages().getMessage(),
                    "uri=" + request.getRequestURI(), ((KnifeOauth2AuthenticationException) exception).getErrorMessages().getUserMessage(), stackTraces);
        }else if(exception instanceof OAuth2AuthenticationException) {
            errorResponsePayload = new SecurityKnifeErrorResponsePayload(
                    ((OAuth2AuthenticationException) exception).getError().getErrorCode() + " / " + ((OAuth2AuthenticationException) exception).getError().getDescription(),
                    "uri=" + request.getRequestURI(),
                    iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_LOGIN_FAILURE),
                    stackTraces);
        }else{
            errorResponsePayload = new SecurityKnifeErrorResponsePayload(
                    exception.getMessage(),
                    "uri=" + request.getRequestURI(),
                    iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_LOGIN_ERROR),
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
