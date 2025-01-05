package io.github.patternknife.securityhelper.oauth2.api.config.security.response.auth.authentication;


import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.patternknife.securityhelper.oauth2.api.config.logger.KnifeSecurityLogConfig;
import io.github.patternknife.securityhelper.oauth2.api.config.security.message.DefaultSecurityUserExceptionMessage;
import io.github.patternknife.securityhelper.oauth2.api.config.security.message.ISecurityUserExceptionMessageService;
import io.github.patternknife.securityhelper.oauth2.api.config.security.response.error.dto.SecurityKnifeErrorResponsePayload;
import io.github.patternknife.securityhelper.oauth2.api.config.security.response.error.exception.KnifeOauth2AuthenticationException;
import io.github.patternknife.securityhelper.oauth2.api.config.security.response.error.util.ExceptionKnifeUtils;
import jakarta.servlet.ServletException;
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
import java.util.ArrayList;
import java.util.List;


@RequiredArgsConstructor
public class DefaultWebAuthenticationFailureHandlerImpl implements AuthenticationFailureHandler {

    private static final Logger logger = LoggerFactory.getLogger(DefaultWebAuthenticationFailureHandlerImpl.class);

    private final ISecurityUserExceptionMessageService iSecurityUserExceptionMessageService;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        // SecurityKnifeExceptionHandler does NOT handle this error.
        logger.error("Authentication failed: ", exception);

        String errorMessage = "An unexpected error occurred.";
        List<String> errorDetails = new ArrayList<>();
        // Extract error messages if the exception is of type KnifeOauth2AuthenticationException
        if (exception instanceof KnifeOauth2AuthenticationException) {
            KnifeOauth2AuthenticationException oauth2Exception = (KnifeOauth2AuthenticationException) exception;
            errorMessage = oauth2Exception.getErrorMessages().getUserMessage();
        }

        if(errorMessage.equals("Authorization code missing in GET request")){
            request.getRequestDispatcher("/login").forward(request, response);
        }else {

            // Redirect to /error with query parameters
            request.setAttribute("errorMessage", errorMessage);
            request.setAttribute("errorDetails", errorDetails);

            request.getRequestDispatcher("/error").forward(request, response);
        }
    }
}
