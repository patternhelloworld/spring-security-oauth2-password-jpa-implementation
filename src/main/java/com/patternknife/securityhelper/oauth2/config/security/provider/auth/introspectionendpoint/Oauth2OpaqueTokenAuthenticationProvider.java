package com.patternknife.securityhelper.oauth2.config.security.provider.auth.introspectionendpoint;

import com.patternknife.securityhelper.oauth2.config.security.principal.AccessTokenUserInfo;
import com.patternknife.securityhelper.oauth2.config.security.serivce.persistence.authorization.OAuth2AuthorizationServiceImpl;
import com.patternknife.securityhelper.oauth2.config.security.serivce.userdetail.ConditionalDetailsService;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.introspection.BadOpaqueTokenException;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionException;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import java.time.Instant;

@Component
public final class Oauth2OpaqueTokenAuthenticationProvider implements AuthenticationProvider {

    private final Log logger = LogFactory.getLog(this.getClass());

    private final OpaqueTokenIntrospector introspector;

    private OpaqueTokenAuthenticationConverter authenticationConverter = Oauth2OpaqueTokenAuthenticationProvider::convert;

    private final OAuth2AuthorizationServiceImpl authorizationService;
    private final ConditionalDetailsService conditionalDetailsService;


    public Oauth2OpaqueTokenAuthenticationProvider(OpaqueTokenIntrospector introspector, OAuth2AuthorizationServiceImpl authorizationService,
                                                   ConditionalDetailsService conditionalDetailsService) {
        Assert.notNull(introspector, "introspector cannot be null");
        this.introspector = introspector;
        this.authorizationService = authorizationService;
        this.conditionalDetailsService = conditionalDetailsService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (!(authentication instanceof BearerTokenAuthenticationToken bearer)) {
            return null;
        } else {
            OAuth2AuthenticatedPrincipal principal = this.getOAuth2AuthenticatedPrincipal(bearer);


            Authentication result = this.authenticationConverter.convert(bearer.getToken(), principal);
            if (result == null) {
                return null;
            } else {
                if (AbstractAuthenticationToken.class.isAssignableFrom(result.getClass())) {
                    AbstractAuthenticationToken auth = (AbstractAuthenticationToken)result;
                    if (auth.getDetails() == null) {
                        auth.setDetails(bearer.getDetails());
                    }
                }

                this.logger.debug("Authenticated token");
                return result;
            }
        }
    }

    private OAuth2AuthenticatedPrincipal getOAuth2AuthenticatedPrincipal(BearerTokenAuthenticationToken bearer) {
        try {
            return this.introspector.introspect(bearer.getToken());
        } catch (BadOpaqueTokenException var3) {
            this.logger.debug("Failed to authenticate since token was invalid");
            throw new InvalidBearerTokenException(var3.getMessage(), var3);
        } catch (OAuth2IntrospectionException var4) {
            throw new AuthenticationServiceException(var4.getMessage(), var4);
        }
    }

    public boolean supports(Class<?> authentication) {
        return BearerTokenAuthenticationToken.class.isAssignableFrom(authentication);
    }

    static BearerTokenAuthentication convert(String introspectedToken, OAuth2AuthenticatedPrincipal authenticatedPrincipal) {
        Instant iat = (Instant) authenticatedPrincipal.getAttribute("iat");
        Instant exp = (Instant) authenticatedPrincipal.getAttribute("exp");
        OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, introspectedToken, iat, exp);
        return new BearerTokenAuthentication(authenticatedPrincipal, accessToken, authenticatedPrincipal.getAuthorities());
    }

    public void setAuthenticationConverter(OpaqueTokenAuthenticationConverter authenticationConverter) {
        Assert.notNull(authenticationConverter, "authenticationConverter cannot be null");
        this.authenticationConverter = authenticationConverter;
    }


    public BearerTokenAuthentication convert(HttpServletRequest httpServletRequest) {

        String token = httpServletRequest.getParameter("token");

        OAuth2Authorization oAuth2Authorization = authorizationService.findByToken(token, OAuth2TokenType.ACCESS_TOKEN);

        if(oAuth2Authorization == null || oAuth2Authorization.getAccessToken() == null || oAuth2Authorization.getAccessToken().isExpired()
                || oAuth2Authorization.getRefreshToken() == null || oAuth2Authorization.getRefreshToken().isExpired()){
            return null;
        }

        OAuth2AuthenticatedPrincipal oAuth2AuthenticatedPrincipal = (AccessTokenUserInfo) conditionalDetailsService.loadUserByUsername(oAuth2Authorization.getPrincipalName(), (String)oAuth2Authorization.getAttributes().get("client_id"));

        OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, token, oAuth2Authorization.getAccessToken().getToken().getIssuedAt(), oAuth2Authorization.getAccessToken().getToken().getExpiresAt());
        return new BearerTokenAuthentication(oAuth2AuthenticatedPrincipal, accessToken, oAuth2AuthenticatedPrincipal.getAuthorities());
    }
}