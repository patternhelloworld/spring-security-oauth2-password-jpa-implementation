package com.patternhelloworld.securityhelper.oauth2.client.config.securityimpl.response;


import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.message.ISecurityUserExceptionMessageService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;

@Primary
@Qualifier("webAuthenticationSuccessHandler")
@Configuration
@RequiredArgsConstructor
public class CustomWebAuthenticationSuccessHandlerImpl implements AuthenticationSuccessHandler {

    private final ISecurityUserExceptionMessageService iSecurityUserExceptionMessageService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        OAuth2AuthorizationCodeAuthenticationToken oAuth2AuthorizationCodeAuthenticationToken = (OAuth2AuthorizationCodeAuthenticationToken) authentication;

        String redirectUri = oAuth2AuthorizationCodeAuthenticationToken.getRedirectUri();
        String authorizationCode = oAuth2AuthorizationCodeAuthenticationToken.getCode();
        String state = oAuth2AuthorizationCodeAuthenticationToken.getAdditionalParameters().get("state").toString();

        response.sendRedirect(redirectUri+"?code="+authorizationCode+"&state="+state);
    }
}
