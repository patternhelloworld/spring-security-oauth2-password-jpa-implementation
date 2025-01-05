package com.patternknife.securityhelper.oauth2.client.config.securityimpl.introspector;

import io.github.patternknife.securityhelper.oauth2.api.config.security.message.DefaultSecurityUserExceptionMessage;
import io.github.patternknife.securityhelper.oauth2.api.config.security.message.ISecurityUserExceptionMessageService;
import io.github.patternknife.securityhelper.oauth2.api.config.security.response.error.exception.KnifeOauth2AuthenticationException;
import io.github.patternknife.securityhelper.oauth2.api.config.security.serivce.persistence.authorization.OAuth2AuthorizationServiceImpl;
import io.github.patternknife.securityhelper.oauth2.api.config.security.serivce.userdetail.ConditionalDetailsService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.resource.introspection.SpringOpaqueTokenIntrospector;
import org.springframework.stereotype.Component;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;

/*
*   Set this to your resource servers
* */
@Component
public class CustomResourceServerTokenIntrospector implements OpaqueTokenIntrospector {

    private final OpaqueTokenIntrospector delegate;

    /*
    *   api : resource servers call the authorization server
    *   database : the database is shared with the authorization server and resource servers
    * */
    String introspectionType;

    private final OAuth2AuthorizationServiceImpl authorizationService;
    private final ConditionalDetailsService conditionalDetailsService;
    private final ISecurityUserExceptionMessageService iSecurityUserExceptionMessageService;


    public CustomResourceServerTokenIntrospector(
            OAuth2AuthorizationServiceImpl authorizationService,
            ConditionalDetailsService conditionalDetailsService,
            ISecurityUserExceptionMessageService iSecurityUserExceptionMessageService,
            @Value("${patternknife.securityhelper.oauth2.introspection.type:database}") String introspectionType,
            @Value("${patternknife.securityhelper.oauth2.introspection.uri:default-introspect-uri}") String introspectionUri,
            @Value("${patternknife.securityhelper.oauth2.introspection.client-id:default-client-id}") String clientId,
            @Value("${patternknife.securityhelper.oauth2.introspection.client-secret:default-client-secret}") String clientSecret) {

        this.authorizationService = authorizationService;
        this.conditionalDetailsService = conditionalDetailsService;
        this.iSecurityUserExceptionMessageService = iSecurityUserExceptionMessageService;

        this.introspectionType = introspectionType;

        this.delegate = new SpringOpaqueTokenIntrospector(introspectionUri, clientId, clientSecret);
    }

    @Override
    public OAuth2AuthenticatedPrincipal introspect(String token) {
        if(introspectionType.equals("api")) {
            try {
                return delegate.introspect(token);
            } catch (Exception e) {
                throw new KnifeOauth2AuthenticationException(e.getMessage());
            }
        } else if (introspectionType.equals("database")) {
            OAuth2Authorization oAuth2Authorization = authorizationService.findByToken(token, OAuth2TokenType.ACCESS_TOKEN);

            if(oAuth2Authorization == null || oAuth2Authorization.getAccessToken() == null || oAuth2Authorization.getAccessToken().isExpired()
                    || oAuth2Authorization.getRefreshToken() == null || oAuth2Authorization.getRefreshToken().isExpired()){
                throw new KnifeOauth2AuthenticationException(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_TOKEN_FAILURE));
            }
            return (OAuth2AuthenticatedPrincipal) conditionalDetailsService.loadUserByUsername(oAuth2Authorization.getPrincipalName(), (String) oAuth2Authorization.getAttributes().get("client_id"));
        }else{
            throw new KnifeOauth2AuthenticationException("Wrong introspection type : " + introspectionType);
        }
    }
}

