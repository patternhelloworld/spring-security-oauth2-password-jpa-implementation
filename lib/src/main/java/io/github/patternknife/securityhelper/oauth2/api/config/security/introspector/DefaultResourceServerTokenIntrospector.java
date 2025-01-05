package io.github.patternknife.securityhelper.oauth2.api.config.security.introspector;


import io.github.patternknife.securityhelper.oauth2.api.config.security.message.DefaultSecurityUserExceptionMessage;
import io.github.patternknife.securityhelper.oauth2.api.config.security.message.ISecurityUserExceptionMessageService;
import io.github.patternknife.securityhelper.oauth2.api.config.security.response.error.exception.KnifeOauth2AuthenticationException;
import io.github.patternknife.securityhelper.oauth2.api.config.security.serivce.persistence.authorization.OAuth2AuthorizationServiceImpl;
import io.github.patternknife.securityhelper.oauth2.api.config.security.serivce.userdetail.ConditionalDetailsService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.SpringOpaqueTokenIntrospector;
import org.springframework.stereotype.Component;


public class DefaultResourceServerTokenIntrospector implements OpaqueTokenIntrospector {

    private final OpaqueTokenIntrospector delegate;

    /*
     *   api : resource servers call the authorization server
     *   database : the database is shared with the authorization server and resource servers
     * */
    String introspectionType;

    private final OAuth2AuthorizationServiceImpl authorizationService;
    private final ConditionalDetailsService conditionalDetailsService;
    private final ISecurityUserExceptionMessageService iSecurityUserExceptionMessageService;


    public DefaultResourceServerTokenIntrospector(
            OAuth2AuthorizationServiceImpl authorizationService,
            ConditionalDetailsService conditionalDetailsService,
            ISecurityUserExceptionMessageService iSecurityUserExceptionMessageService,
            String introspectionType,
            String introspectionUri,
            String clientId,
            String clientSecret) {

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
