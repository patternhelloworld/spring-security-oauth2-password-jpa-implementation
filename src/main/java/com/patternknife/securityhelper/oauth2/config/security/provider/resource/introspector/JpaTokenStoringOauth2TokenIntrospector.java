package com.patternknife.securityhelper.oauth2.config.security.provider.resource.introspector;


import com.patternknife.securityhelper.oauth2.config.response.error.message.SecurityExceptionMessage;
import com.patternknife.securityhelper.oauth2.config.response.error.exception.auth.UnauthenticatedException;
import com.patternknife.securityhelper.oauth2.config.security.serivce.OAuth2AuthorizationServiceImpl;
import com.patternknife.securityhelper.oauth2.config.security.principal.AccessTokenUserInfo;
import com.patternknife.securityhelper.oauth2.config.security.principal.AdditionalAccessTokenUserInfo;
import com.patternknife.securityhelper.oauth2.config.security.serivce.userdetail.AdminDetailsService;
import com.patternknife.securityhelper.oauth2.config.security.serivce.userdetail.CustomerDetailsService;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.resource.introspection.NimbusOpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;


public class JpaTokenStoringOauth2TokenIntrospector implements OpaqueTokenIntrospector {


   private OpaqueTokenIntrospector delegate =
            new NimbusOpaqueTokenIntrospector(
                    "http://localhost:8300/oauth2/introspect",
                    "barClient",
                    "barClientSecret"
            );

    private final OAuth2AuthorizationServiceImpl authorizationService;
    private final CustomerDetailsService customerDetailsService;
    private final AdminDetailsService adminDetailsService;

    public JpaTokenStoringOauth2TokenIntrospector(OAuth2AuthorizationServiceImpl authorizationService, CustomerDetailsService customerDetailsService, AdminDetailsService adminDetailsService) {
        this.authorizationService = authorizationService;
        this.customerDetailsService = customerDetailsService;
        this.adminDetailsService = adminDetailsService;
    }

    @Override
    public OAuth2AuthenticatedPrincipal introspect(String token) {

/*        try {
            OAuth2AuthenticatedPrincipal principal = delegate.introspect(token);
            return principal;
        }catch (Exception e){
            //throw e;
            throw new UnauthenticatedException(e.getMessage());
        }*/

       OAuth2Authorization oAuth2Authorization = authorizationService.findByToken(token, OAuth2TokenType.ACCESS_TOKEN);

        if(oAuth2Authorization == null || oAuth2Authorization.getAccessToken() == null || oAuth2Authorization.getAccessToken().isExpired()
            || oAuth2Authorization.getRefreshToken() == null || oAuth2Authorization.getRefreshToken().isExpired()){
            throw new UnauthenticatedException(SecurityExceptionMessage.AUTHENTICATION_FAILURE.getMessage());
            //return null;
        }

        if (oAuth2Authorization.getAttributes().get("client_id").equals(AdditionalAccessTokenUserInfo.UserType.ADMIN.getValue())) {
            return (AccessTokenUserInfo) adminDetailsService.loadUserByUsername(oAuth2Authorization.getPrincipalName());
        } else if (oAuth2Authorization.getAttributes().get("client_id").equals(AdditionalAccessTokenUserInfo.UserType.CUSTOMER.getValue())) {
            return (AccessTokenUserInfo) customerDetailsService.loadUserByUsername(oAuth2Authorization.getPrincipalName());
        } else {
            throw new UnauthenticatedException(SecurityExceptionMessage.AUTHENTICATION_ERROR.getMessage());
        }
    }
}