package com.patternhelloworld.securityhelper.oauth2.client.config.securityimpl.response;

import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.message.ISecurityUserExceptionMessageService;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.response.error.exception.EasyPlusOauth2AuthenticationException;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.util.EasyPlusErrorCodeConstants;
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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Primary
@Qualifier("webAuthenticationFailureHandler")
@Configuration
@RequiredArgsConstructor
public class CustomWebAuthenticationFailureHandlerImpl implements AuthenticationFailureHandler {

    private static final Logger logger = LoggerFactory.getLogger(CustomWebAuthenticationFailureHandlerImpl.class);

    private final ISecurityUserExceptionMessageService iSecurityUserExceptionMessageService;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        // SecurityEasyPlusExceptionHandler does NOT handle this error.
        logger.error("Authentication failed: ", exception);

        String errorMessage = "An unexpected error occurred.";
        List<String> errorDetails = new ArrayList<>();

        EasyPlusOauth2AuthenticationException oauth2Exception;
        // Extract error messages if the exception is of type EasyPlusOauth2AuthenticationException
        if (exception instanceof EasyPlusOauth2AuthenticationException) {
            oauth2Exception = (EasyPlusOauth2AuthenticationException) exception;
            errorMessage = oauth2Exception.getErrorMessages().getUserMessage() + "(" + oauth2Exception.getErrorMessages().getErrorCode() + ")";

            if(oauth2Exception.getError().getErrorCode().equals(EasyPlusErrorCodeConstants.REDIRECT_TO_LOGIN)){
                request.getRequestDispatcher("/login").forward(request, response);
                return;
            }
            if(oauth2Exception.getError().getErrorCode().equals(EasyPlusErrorCodeConstants.REDIRECT_TO_CONSENT)){
                // Construct full URL
                String fullURL = request.getRequestURL().toString();
                if (request.getQueryString() != null) {
                    fullURL += "?" + request.getQueryString();
                }
                Map<String, String> consentAttributes = new HashMap<>();
                consentAttributes.put("clientId", request.getParameter("client_id"));
                consentAttributes.put("redirectUri", request.getParameter("redirect_uri"));
                consentAttributes.put("code", request.getParameter("code"));
                consentAttributes.put("state", request.getParameter("state"));
                consentAttributes.put("scope", request.getParameter("scope"));
                if(request.getParameter("code_challenge") == null || request.getParameter("code_challenge_method") == null) {
                    consentAttributes.put("codeChallenge", request.getParameter("code_challenge"));
                    consentAttributes.put("codeChallengeMethod", request.getParameter("code_challenge_method"));
                }
                consentAttributes.put("consentRequestURI", fullURL);

                request.setAttribute("consentAttributes", consentAttributes);
                request.getRequestDispatcher("/consent").forward(request, response);
                return;
            }
        }
        request.setAttribute("errorMessage", errorMessage);
        request.setAttribute("errorDetails", errorDetails);

        request.getRequestDispatcher("/error").forward(request, response);

    }
}
