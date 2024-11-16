package io.github.patternknife.securityhelper.oauth2.api.config.security.response.auth.authentication;


import io.github.patternknife.securityhelper.oauth2.api.config.logger.KnifeSecurityLogConfig;
import io.github.patternknife.securityhelper.oauth2.api.config.security.response.error.dto.SecurityKnifeErrorResponsePayload;
import io.github.patternknife.securityhelper.oauth2.api.config.security.response.error.exception.KnifeOauth2AuthenticationException;
import io.github.patternknife.securityhelper.oauth2.api.config.security.response.error.util.ExceptionKnifeUtils;
import io.github.patternknife.securityhelper.oauth2.api.config.security.message.DefaultSecurityUserExceptionMessage;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.patternknife.securityhelper.oauth2.api.config.security.message.ISecurityUserExceptionMessageService;
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
public class DefaultAuthenticationFailureHandlerImpl implements AuthenticationFailureHandler {

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
