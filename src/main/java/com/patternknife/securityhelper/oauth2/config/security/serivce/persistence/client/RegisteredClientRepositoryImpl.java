package com.patternknife.securityhelper.oauth2.config.security.serivce.persistence.client;

import com.patternknife.securityhelper.oauth2.config.logger.dto.ErrorMessages;
import com.patternknife.securityhelper.oauth2.config.response.error.exception.auth.CustomOauth2AuthenticationException;
import com.patternknife.securityhelper.oauth2.config.response.error.message.SecurityUserExceptionMessage;
import com.patternknife.securityhelper.oauth2.config.security.OAuth2ClientCachedInfo;
import com.patternknife.securityhelper.oauth2.config.security.dao.OauthClientDetailRepository;
import com.patternknife.securityhelper.oauth2.config.security.entity.OauthClientDetail;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Repository;

import java.time.Duration;
import java.util.Arrays;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Repository
@RequiredArgsConstructor
public class RegisteredClientRepositoryImpl implements RegisteredClientRepository {

    private final OauthClientDetailRepository oauthClientDetailRepository;

    @Override
    public void save(RegisteredClient registeredClient) {

        OauthClientDetail detail = new OauthClientDetail();
        detail.setClientId(registeredClient.getClientId());
        detail.setClientSecret(registeredClient.getClientSecret());
        detail.setScope(String.join(",", registeredClient.getScopes()));

        String grantTypes = registeredClient.getAuthorizationGrantTypes().stream()
                .map(AuthorizationGrantType::getValue)
                .collect(Collectors.joining(","));
        detail.setAuthorizedGrantTypes(grantTypes);


        detail.setResourceIds(OAuth2ClientCachedInfo.RESOURCE_IDS.getValue());

        detail.setAccessTokenValidity(registeredClient.getTokenSettings().getAccessTokenTimeToLive().getSeconds());
        detail.setRefreshTokenValidity(registeredClient.getTokenSettings().getRefreshTokenTimeToLive().getSeconds());

        oauthClientDetailRepository.save(detail);
    }

    @Override
    public @NotNull RegisteredClient findById(String id) throws CustomOauth2AuthenticationException {
        // Assuming the ID is the client ID for simplification. Adjust if necessary.
        return oauthClientDetailRepository.findById(id)
                .map(this::mapToRegisteredClient)
                .orElseThrow(()->
                        new CustomOauth2AuthenticationException(ErrorMessages.builder().message("Couldn't find the ID : " + id)
                                .userMessage(SecurityUserExceptionMessage.AUTHENTICATION_LOGIN_FAILURE.getMessage()).build()));
    }
    @Override
    public @NotNull RegisteredClient findByClientId(String clientId) throws CustomOauth2AuthenticationException {
        return oauthClientDetailRepository.findById(clientId)
                .map(this::mapToRegisteredClient)
                .orElseThrow(()->
                        new CustomOauth2AuthenticationException(ErrorMessages.builder().message("Couldn't find the client ID : " + clientId)
                                .userMessage(SecurityUserExceptionMessage.AUTHENTICATION_LOGIN_FAILURE.getMessage()).build()));
    }


    private RegisteredClient mapToRegisteredClient(OauthClientDetail detail) {
        Set<String> scopesSet = Arrays.stream(detail.getScope().split(","))
                .map(String::trim)
                .collect(Collectors.toSet());

        Set<AuthorizationGrantType> grantTypesSet = Arrays.stream(detail.getAuthorizedGrantTypes().split(","))
                .map(String::trim)
                .map(AuthorizationGrantType::new)
                .collect(Collectors.toSet());

        return RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(detail.getClientId())
                .clientSecret(detail.getClientSecret())
                .clientName(detail.getClientId()) // Adjust according to your needs.
                .clientAuthenticationMethods(authenticationMethods ->
                        authenticationMethods.add(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)) // Adjust based on your entity
                .authorizationGrantTypes(grantTypes -> grantTypes.addAll(grantTypesSet))
                .scopes(scopes -> scopes.addAll(scopesSet))
                .redirectUri("")
                // Add additional configurations as needed, e.g., redirectUris
                .tokenSettings(TokenSettings.builder()
                        .accessTokenFormat(OAuth2TokenFormat.REFERENCE)
                        .accessTokenTimeToLive(Duration.ofSeconds(detail.getAccessTokenValidity()))
                        .refreshTokenTimeToLive(Duration.ofSeconds(detail.getRefreshTokenValidity()))
                        .build())
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build()) // Adjust accordingly
                .build();
    }


}
