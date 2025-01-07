package io.github.patternhelloworld.securityhelper.oauth2.api.config.security.provider.auth.introspectionendpoint;

import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.response.error.exception.EasyPlusOauth2AuthenticationException;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.serivce.persistence.authorization.OAuth2AuthorizationServiceImpl;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.serivce.userdetail.ConditionalDetailsService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenIntrospection;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenIntrospectionAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

@Component
public final class IntrospectOpaqueTokenAuthenticationProvider implements AuthenticationProvider {

    private final Log logger = LogFactory.getLog(this.getClass());


    private final OAuth2AuthorizationServiceImpl authorizationService;
    private final ConditionalDetailsService conditionalDetailsService;


    public IntrospectOpaqueTokenAuthenticationProvider(OAuth2AuthorizationServiceImpl authorizationService,
                                                       ConditionalDetailsService conditionalDetailsService) {

        this.authorizationService = authorizationService;
        this.conditionalDetailsService = conditionalDetailsService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (!(authentication instanceof OAuth2TokenIntrospectionAuthenticationToken)) {
            return null;
        } else {

            String bearerAccessToken = ((OAuth2TokenIntrospectionAuthenticationToken) authentication).getToken();

            OAuth2Authorization oAuth2Authorization = authorizationService.findByToken(bearerAccessToken, OAuth2TokenType.ACCESS_TOKEN);
            if(oAuth2Authorization == null) {
                throw new EasyPlusOauth2AuthenticationException();
            }


            OAuth2ClientAuthenticationToken oAuth2ClientAuthenticationToken = (OAuth2ClientAuthenticationToken)authentication.getPrincipal();

            RegisteredClient registeredClient = oAuth2ClientAuthenticationToken.getRegisteredClient();

            UserDetails userDetails = conditionalDetailsService.loadUserByUsername(oAuth2Authorization.getPrincipalName(), registeredClient.getClientName());


            Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();

            assert oAuth2Authorization != null;
            assert registeredClient != null;

            return new OAuth2TokenIntrospectionAuthenticationToken(
                    bearerAccessToken,
                    clientPrincipal,
                    OAuth2TokenIntrospection.builder()
                            .active(true)
                            .tokenType(OAuth2TokenType.ACCESS_TOKEN.getValue())
                            .username(oAuth2Authorization.getPrincipalName())
                            .clientId(registeredClient.getClientId())
                            .claim("App-Token", Objects.requireNonNull(oAuth2Authorization.getAttribute("App-Token") != null ? oAuth2Authorization.getAttribute("App-Token") : ""))
                            .claims(claims -> {
                                List<String> authorities = userDetails.getAuthorities().stream()
                                        .map(GrantedAuthority::getAuthority)
                                        .collect(Collectors.toList());
                                claims.put("authorities", authorities);
                            })
                            .build()
            );

        }
    }

    public boolean supports(Class<?> authentication) {
        return OAuth2TokenIntrospectionAuthenticationToken.class.isAssignableFrom(authentication);
    }


}