package io.github.patternhelloworld.securityhelper.oauth2.api.config.security.response.auth.authentication;


import io.github.patternhelloworld.securityhelper.oauth2.api.config.logger.EasyPlusSecurityLogConfig;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.response.error.dto.SecurityEasyPlusErrorResponsePayload;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.response.error.exception.EasyPlusOauth2AuthenticationException;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.response.error.util.ExceptionEasyPlusUtils;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.message.DefaultSecurityUserExceptionMessage;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.message.ISecurityUserExceptionMessageService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import java.io.IOException;


@RequiredArgsConstructor
public class DefaultApiAuthenticationFailureHandlerImpl implements AuthenticationFailureHandler {

    private static final Logger logger = LoggerFactory.getLogger(EasyPlusSecurityLogConfig.class);

    private final ISecurityUserExceptionMessageService iSecurityUserExceptionMessageService;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception)
            throws IOException {

        SecurityEasyPlusErrorResponsePayload errorResponsePayload;
        String stackTraces = ExceptionEasyPlusUtils.getAllStackTraces(exception);
        if(exception instanceof EasyPlusOauth2AuthenticationException){
            errorResponsePayload = new SecurityEasyPlusErrorResponsePayload(((EasyPlusOauth2AuthenticationException) exception).getErrorMessages().getMessage(),
                    "uri=" + request.getRequestURI(), ((EasyPlusOauth2AuthenticationException) exception).getErrorMessages().getUserMessage(), stackTraces);
        }else if(exception instanceof OAuth2AuthenticationException) {
            errorResponsePayload = new SecurityEasyPlusErrorResponsePayload(
                    ((OAuth2AuthenticationException) exception).getError().getErrorCode() + " / " + ((OAuth2AuthenticationException) exception).getError().getDescription(),
                    "uri=" + request.getRequestURI(),
                    iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_LOGIN_FAILURE),
                    stackTraces);
        }else{
            errorResponsePayload = new SecurityEasyPlusErrorResponsePayload(
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
