package com.patternhelloworld.securityhelper.oauth2.client.config.securityimpl.guard;

import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.core.EasyPlusUserInfo;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.message.DefaultSecurityUserExceptionMessage;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.message.ISecurityUserExceptionMessageService;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.response.error.dto.EasyPlusErrorMessages;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.response.error.exception.EasyPlusOauth2AuthenticationException;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.serivce.persistence.authorization.OAuth2AuthorizationServiceImpl;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.serivce.userdetail.ConditionalDetailsService;


import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionAuthenticatedPrincipal;

public class AccessTokenUserInfoConverter {

    public static EasyPlusUserInfo<?> from(Object principal,
                                        ConditionalDetailsService conditionalDetailsService,
                                        OAuth2AuthorizationServiceImpl authorizationService, ISecurityUserExceptionMessageService iSecurityUserExceptionMessageService) {

        EasyPlusUserInfo<?> easyPlusUserInfo;
        if (principal instanceof EasyPlusUserInfo) {
            return ((EasyPlusUserInfo<?>) principal);
        } else if (principal instanceof OAuth2IntrospectionAuthenticatedPrincipal) {
            String userName = ((OAuth2IntrospectionAuthenticatedPrincipal) principal).getUsername();
            String clientId = ((OAuth2IntrospectionAuthenticatedPrincipal) principal).getClientId();
            String appToken = ((OAuth2IntrospectionAuthenticatedPrincipal) principal).getAttribute("App-Token");

            OAuth2Authorization oAuth2Authorization = authorizationService.findByUserNameAndClientIdAndAppToken(userName, clientId, appToken);
            if (oAuth2Authorization == null) {
                throw new EasyPlusOauth2AuthenticationException(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_LOGIN_FAILURE));
            }

            return (EasyPlusUserInfo<?>) conditionalDetailsService.loadUserByUsername(userName, clientId);
        }else {
            throw new EasyPlusOauth2AuthenticationException(EasyPlusErrorMessages.builder().message("Wrong principal : " +  principal.toString()).userMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_TOKEN_ERROR.getMessage()).build());
        }

    }
}
