package io.github.patternhelloworld.securityhelper.oauth2.api.config.security.response.auth.authentication;


import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.message.ISecurityUserExceptionMessageService;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.response.error.exception.EasyPlusOauth2AuthenticationException;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.util.ErrorCodeConstants;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;


@RequiredArgsConstructor
public class DefaultWebAuthenticationFailureHandlerImpl implements AuthenticationFailureHandler {

    private static final Logger logger = LoggerFactory.getLogger(DefaultWebAuthenticationFailureHandlerImpl.class);

    private final ISecurityUserExceptionMessageService iSecurityUserExceptionMessageService;

    // SecurityEasyPlusExceptionHandler does NOT handle this error.
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {

        logger.error("Authentication failed: ", exception);

        String errorMessage = "An unexpected error occurred.";
        List<String> errorDetails = new ArrayList<>();

        EasyPlusOauth2AuthenticationException oauth2Exception;
        // Extract error messages if the exception is of type EasyPlusOauth2AuthenticationException
        if (exception instanceof EasyPlusOauth2AuthenticationException) {
            oauth2Exception = (EasyPlusOauth2AuthenticationException) exception;
            errorMessage = oauth2Exception.getErrorMessages().getUserMessage();

            if(oauth2Exception.getError().getErrorCode().equals(ErrorCodeConstants.REDIRECT_TO_LOGIN)){
                request.getRequestDispatcher("/login").forward(request, response);
                return;
            }
            if(oauth2Exception.getError().getErrorCode().equals(ErrorCodeConstants.REDIRECT_TO_CONSENT)){
                request.getRequestDispatcher("/consent").forward(request, response);
                return;
            }
        }
        request.setAttribute("errorMessage", errorMessage);
        request.setAttribute("errorDetails", errorDetails);

        request.getRequestDispatcher("/error").forward(request, response);
    }
}
