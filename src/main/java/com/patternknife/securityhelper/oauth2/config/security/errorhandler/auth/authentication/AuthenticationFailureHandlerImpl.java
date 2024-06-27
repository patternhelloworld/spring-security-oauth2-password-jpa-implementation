package com.patternknife.securityhelper.oauth2.config.security.errorhandler.auth.authentication;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.patternknife.securityhelper.oauth2.config.logger.dto.ErrorDetails;
import com.patternknife.securityhelper.oauth2.config.response.error.CustomExceptionUtils;
import com.patternknife.securityhelper.oauth2.config.response.error.exception.auth.CustomOauth2AuthenticationException;
import com.patternknife.securityhelper.oauth2.config.response.error.message.SecurityUserExceptionMessage;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import java.io.IOException;


public class AuthenticationFailureHandlerImpl implements AuthenticationFailureHandler {

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception)
            throws IOException {

        ErrorDetails errorDetails;
        String stackTraces = CustomExceptionUtils.getAllStackTraces(exception);
        if(exception instanceof CustomOauth2AuthenticationException){
            errorDetails = new ErrorDetails(((CustomOauth2AuthenticationException) exception).getErrorMessages().getMessage(),
                    "uri=" + request.getRequestURI(), ((CustomOauth2AuthenticationException) exception).getErrorMessages().getUserMessage(), stackTraces);
        }else if(exception instanceof OAuth2AuthenticationException) {
            errorDetails = new ErrorDetails(
                    ((OAuth2AuthenticationException) exception).getError().getErrorCode(),
                    "uri=" + request.getRequestURI(),
                    ((OAuth2AuthenticationException) exception).getError().getDescription(),
                    stackTraces);
        }else{
            errorDetails = new ErrorDetails(
                    exception.getMessage(),
                    "uri=" + request.getRequestURI(),
                    SecurityUserExceptionMessage.AUTHENTICATION_LOGIN_FAILURE.getMessage(),
                    stackTraces);
        }

        // Set response status
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType("application/json");

        // Write the error details to the response
        response.getWriter().write(new ObjectMapper().writeValueAsString(errorDetails));

    }
}
