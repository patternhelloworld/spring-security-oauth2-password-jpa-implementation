package com.patternknife.securityhelper.oauth2.client.config.securityimpl.response;


import io.github.patternknife.securityhelper.oauth2.api.config.security.message.ISecurityUserExceptionMessageService;
import io.github.patternknife.securityhelper.oauth2.api.config.security.response.error.exception.KnifeOauth2AuthenticationException;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

@Primary
@Qualifier("webAuthenticationFailureHandler")
@Configuration
@RequiredArgsConstructor
public class CustomWebAuthenticationFailureHandlerImpl implements AuthenticationFailureHandler {

    private static final Logger logger = LoggerFactory.getLogger(CustomWebAuthenticationFailureHandlerImpl.class);

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
