package io.github.patternhelloworld.securityhelper.oauth2.api.config.security.introspector;

import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.message.DefaultSecurityUserExceptionMessage;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.message.ISecurityUserExceptionMessageService;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.response.error.dto.EasyPlusErrorMessages;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.response.error.exception.EasyPlusOauth2AuthenticationException;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.serivce.persistence.authorization.OAuth2AuthorizationServiceImpl;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.serivce.userdetail.ConditionalDetailsService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.SpringOpaqueTokenIntrospector;

import java.util.Arrays;
import java.util.Map;


public class DefaultResourceServerTokenIntrospector implements OpaqueTokenIntrospector {

    private final OpaqueTokenIntrospector delegate;
    private final JwtDecoder jwtDecoder;

    /*
     *   api : resource servers call the authorization server
     *   database : the database is shared with the authorization server and resource servers
     *   decode : JWT
     * */
    String introspectionType;

    private final OAuth2AuthorizationServiceImpl authorizationService;
    private final ConditionalDetailsService conditionalDetailsService;
    private final ISecurityUserExceptionMessageService iSecurityUserExceptionMessageService;


    public DefaultResourceServerTokenIntrospector(
            OAuth2AuthorizationServiceImpl authorizationService,
            ConditionalDetailsService conditionalDetailsService,
            ISecurityUserExceptionMessageService iSecurityUserExceptionMessageService,
            @Value("${patternhelloworld.securityhelper.oauth2.introspection.type:database}") String introspectionType,
            @Value("${patternhelloworld.securityhelper.oauth2.introspection.uri:default-introspect-uri}") String introspectionUri,
            @Value("${patternhelloworld.securityhelper.oauth2.introspection.client-id:default-client-id}") String clientId,
            @Value("${patternhelloworld.securityhelper.oauth2.introspection.client-secret:default-client-secret}") String clientSecret, JwtDecoder jwtDecoder) {

        this.authorizationService = authorizationService;
        this.conditionalDetailsService = conditionalDetailsService;
        this.iSecurityUserExceptionMessageService = iSecurityUserExceptionMessageService;

        this.introspectionType = introspectionType;

        this.delegate = new SpringOpaqueTokenIntrospector(introspectionUri, clientId, clientSecret);
        this.jwtDecoder = jwtDecoder;
    }

    @Override
    public OAuth2AuthenticatedPrincipal introspect(String token) {
        switch (introspectionType) {
            case "api" -> {
                try {
                    return delegate.introspect(token);
                } catch (Exception e) {
                    throw new EasyPlusOauth2AuthenticationException(EasyPlusErrorMessages.builder().userMessage(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_TOKEN_ERROR)).message(e.getMessage() + Arrays.toString(e.getStackTrace())).build());
                }
            }
            case "database" -> {
                OAuth2Authorization oAuth2Authorization = authorizationService.findByToken(token, OAuth2TokenType.ACCESS_TOKEN);

                if (oAuth2Authorization == null || oAuth2Authorization.getAccessToken() == null || oAuth2Authorization.getAccessToken().isExpired()
                        || oAuth2Authorization.getRefreshToken() == null || oAuth2Authorization.getRefreshToken().isExpired()) {
                    throw new EasyPlusOauth2AuthenticationException(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_TOKEN_FAILURE));
                }
                return (OAuth2AuthenticatedPrincipal) conditionalDetailsService.loadUserByUsername(oAuth2Authorization.getPrincipalName(), (String) oAuth2Authorization.getAttributes().get("client_id"));
            }
            case "decode" -> {
                try {
                    Jwt jwt = jwtDecoder.decode(token);

                    Map<String, Object> claims = jwt.getClaims();
                    String username = (String) claims.get("username");
                    String clientId = (String) claims.get("client_id");

                    return (OAuth2AuthenticatedPrincipal) conditionalDetailsService.loadUserByUsername(username, clientId);
                }catch (Exception e) {
                    throw new EasyPlusOauth2AuthenticationException(EasyPlusErrorMessages.builder().userMessage(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_TOKEN_ERROR)).message(e.getMessage() + Arrays.toString(e.getStackTrace())).build());
                }
            }
            default -> throw new EasyPlusOauth2AuthenticationException("Wrong introspection type : " + introspectionType);
        }
    }
}
