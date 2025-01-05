package com.patternknife.securityhelper.oauth2.client.config.securityimpl.guard;

import io.github.patternknife.securityhelper.oauth2.api.config.security.message.DefaultSecurityUserExceptionMessage;
import io.github.patternknife.securityhelper.oauth2.api.config.security.message.ISecurityUserExceptionMessageService;
import io.github.patternknife.securityhelper.oauth2.api.config.security.response.error.dto.KnifeErrorMessages;
import io.github.patternknife.securityhelper.oauth2.api.config.security.response.error.exception.KnifeOauth2AuthenticationException;
import io.github.patternknife.securityhelper.oauth2.api.config.security.serivce.persistence.authorization.OAuth2AuthorizationServiceImpl;
import io.github.patternknife.securityhelper.oauth2.api.config.security.serivce.userdetail.ConditionalDetailsService;


import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionAuthenticatedPrincipal;

public class AccessTokenUserInfoConverter {

    public static AccessTokenUserInfo from(Object principal,
                                           ConditionalDetailsService conditionalDetailsService,
                                           OAuth2AuthorizationServiceImpl authorizationService, ISecurityUserExceptionMessageService iSecurityUserExceptionMessageService) {

        AccessTokenUserInfo accessTokenUserInfo;
        if (principal instanceof AccessTokenUserInfo) {
            return ((AccessTokenUserInfo) principal);
        } else if (principal instanceof OAuth2IntrospectionAuthenticatedPrincipal) {
            String userName = ((OAuth2IntrospectionAuthenticatedPrincipal) principal).getUsername();
            String clientId = ((OAuth2IntrospectionAuthenticatedPrincipal) principal).getClientId();
            String appToken = ((OAuth2IntrospectionAuthenticatedPrincipal) principal).getAttribute("App-Token");

            OAuth2Authorization oAuth2Authorization = authorizationService.findByUserNameAndClientIdAndAppToken(userName, clientId, appToken);
            if (oAuth2Authorization == null) {
                throw new KnifeOauth2AuthenticationException(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_LOGIN_FAILURE));
            }

            return (AccessTokenUserInfo) conditionalDetailsService.loadUserByUsername(userName, clientId);
        }else {
            throw new KnifeOauth2AuthenticationException(KnifeErrorMessages.builder().message("Wrong principal : " +  principal.toString()).userMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_TOKEN_ERROR.getMessage()).build());
        }

    }
}
