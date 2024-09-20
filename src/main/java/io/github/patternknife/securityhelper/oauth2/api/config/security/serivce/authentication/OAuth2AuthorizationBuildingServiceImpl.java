package io.github.patternknife.securityhelper.oauth2.api.config.security.serivce.authentication;

import io.github.patternknife.securityhelper.oauth2.api.config.security.token.generator.CustomAccessTokenCustomizer;
import io.github.patternknife.securityhelper.oauth2.api.config.security.token.generator.CustomDelegatingOAuth2TokenGenerator;
import io.github.patternknife.securityhelper.oauth2.api.config.security.token.CustomGrantAuthenticationToken;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.UUID;

/*
*
*   The term "build" means a "newly created OAuth2Authorization" (no update)
*
* */
@Component
@RequiredArgsConstructor
public class OAuth2AuthorizationBuildingServiceImpl implements OAuth2AuthorizationBuildingService {

    private final RegisteredClientRepository registeredClientRepository;
    private final CustomDelegatingOAuth2TokenGenerator customTokenGenerator;


    private OAuth2Authorization build(String clientId, UserDetails userDetails,
                                      CustomGrantAuthenticationToken customGrantAuthenticationToken,
                                        OAuth2RefreshToken shouldBePreservedRefreshToken) {

        RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);

        if(AuthorizationServerContextHolder.getContext() == null){

            // If you use "api/v1/traditional-oauth/token", "AuthorizationServerContextHolder.getContext()" is null,
            // while you use "/oauth2/token", "AuthorizationServerContextHolder.getContext()" is NOT null.
            AuthorizationServerContext authorizationServerContext = new AuthorizationServerContext() {
                @Override
                public String getIssuer() {
                    return null;
                }

                @Override
                public AuthorizationServerSettings getAuthorizationServerSettings() {
                    return null;
                }
            };
            AuthorizationServerContextHolder.setContext(authorizationServerContext);
        }


        OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode(
                UUID.randomUUID().toString(),
                Instant.now(), // Issued
                Instant.now().plus(10, ChronoUnit.MINUTES) // Expired
        );

        customTokenGenerator.setCustomizer(
                CustomDelegatingOAuth2TokenGenerator.GeneratorType.ACCESS_TOKEN,
                new CustomAccessTokenCustomizer(userDetails)
        );


        OAuth2Token accessToken = customTokenGenerator.generate(DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(customGrantAuthenticationToken)
                .authorizationServerContext(AuthorizationServerContextHolder.getContext())
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(customGrantAuthenticationToken.getGrantType())
                .authorizationGrant(customGrantAuthenticationToken)
                .authorizedScopes(registeredClient.getScopes())
                .build());


        OAuth2Token refreshToken = shouldBePreservedRefreshToken != null ? shouldBePreservedRefreshToken : customTokenGenerator.generate(DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .authorizationServerContext(AuthorizationServerContextHolder.getContext())
                .principal(customGrantAuthenticationToken)
                .tokenType(OAuth2TokenType.REFRESH_TOKEN)
                .authorizationGrantType(customGrantAuthenticationToken.getGrantType())
                .authorizationGrant(customGrantAuthenticationToken)
                .authorizedScopes(registeredClient.getScopes())
                .build());


        return OAuth2Authorization
                .withRegisteredClient(registeredClient)
                .principalName(userDetails.getUsername())
                .authorizationGrantType(customGrantAuthenticationToken.getGrantType())
                .attribute("authorities", customGrantAuthenticationToken.getAuthorities())
                .attributes(attrs -> attrs.putAll(customGrantAuthenticationToken.getAdditionalParameters()))
                .token(authorizationCode)
                .accessToken(new OAuth2AccessToken(
                        OAuth2AccessToken.TokenType.BEARER,
                        accessToken.getTokenValue(),
                        accessToken.getIssuedAt(),
                        accessToken.getExpiresAt(),
                        registeredClient.getScopes()
                ))
                .refreshToken(new OAuth2RefreshToken(
                        refreshToken.getTokenValue(),
                        refreshToken.getIssuedAt(),
                        refreshToken.getExpiresAt()
                ))
                .build();
    }

    @Override
    public OAuth2Authorization build(UserDetails userDetails, AuthorizationGrantType grantType,String clientId,
                                     Map<String, Object> additionalParameters, OAuth2RefreshToken shouldBePreservedRefreshToken) {

        CustomGrantAuthenticationToken customGrantAuthenticationToken =
                new CustomGrantAuthenticationToken(grantType, userDetails, additionalParameters);

        return build(clientId, userDetails, customGrantAuthenticationToken, shouldBePreservedRefreshToken);
    }

}
