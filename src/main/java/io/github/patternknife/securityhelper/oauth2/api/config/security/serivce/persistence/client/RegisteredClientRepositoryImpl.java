package io.github.patternknife.securityhelper.oauth2.api.config.security.serivce.persistence.client;


import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.patternknife.securityhelper.oauth2.api.config.security.dao.KnifeClientRepository;
import io.github.patternknife.securityhelper.oauth2.api.config.security.entity.KnifeClient;
import io.github.patternknife.securityhelper.oauth2.api.config.security.message.DefaultSecurityUserExceptionMessage;
import io.github.patternknife.securityhelper.oauth2.api.config.security.message.ISecurityUserExceptionMessageService;
import io.github.patternknife.securityhelper.oauth2.api.config.security.response.error.dto.ErrorMessages;
import io.github.patternknife.securityhelper.oauth2.api.config.security.response.error.exception.KnifeOauth2AuthenticationException;
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
import java.util.*;
import java.util.stream.Collectors;

@Repository
@RequiredArgsConstructor
public class RegisteredClientRepositoryImpl implements RegisteredClientRepository {

    private Map<String, @NotNull RegisteredClient> cachedRegisteredClientsByClientId = new HashMap<>();

    private final KnifeClientRepository knifeClientRepository;
    private final ISecurityUserExceptionMessageService iSecurityUserExceptionMessageService;

    private Map<String, Object> parseMap(String data) {
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            return objectMapper.readValue(data, new TypeReference<Map<String, Object>>() {});
        } catch (Exception ex) {
            throw new IllegalArgumentException(ex.getMessage(), ex);
        }
    }

    private String writeMap(Map<String, Object> data) {
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            return objectMapper.writeValueAsString(data);
        } catch (Exception ex) {
            throw new IllegalArgumentException(ex.getMessage(), ex);
        }
    }

    @Override
    public void save(RegisteredClient registeredClient) {

        KnifeClient knifeClient = new KnifeClient();

        knifeClient.setId(UUID.randomUUID().toString());
        knifeClient.setClientId(registeredClient.getClientId());
        knifeClient.setClientSecret(registeredClient.getClientSecret());
        knifeClient.setScopes(String.join(",", registeredClient.getScopes()));

        String grantTypes = registeredClient.getAuthorizationGrantTypes().stream()
                .map(AuthorizationGrantType::getValue)
                .collect(Collectors.joining(","));
        knifeClient.setAuthorizationGrantTypes(grantTypes);

        // Parse and set Client Settings
        String clientSettingsJson = writeMap(registeredClient.getClientSettings().getSettings());
        knifeClient.setClientSettings(clientSettingsJson);

        // Parse and set Token Settings
        String tokenSettingsJson = writeMap(registeredClient.getTokenSettings().getSettings());
        knifeClient.setTokenSettings(tokenSettingsJson);

        knifeClientRepository.save(knifeClient);

        // Cache the registered client as long as the persistence logic above is successful.
        cachedRegisteredClientsByClientId.put(registeredClient.getClientId(), registeredClient);
    }

    @Override
    public @NotNull RegisteredClient findById(String id) throws KnifeOauth2AuthenticationException {
        return knifeClientRepository.findById(id)
                .map(this::mapToRegisteredClient)
                .orElseThrow(()->
                        new KnifeOauth2AuthenticationException(ErrorMessages.builder().message("Couldn't find the ID : " + id)
                                .userMessage(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_WRONG_CLIENT_ID_SECRET)).build()));
    }
    @Override
    public @NotNull RegisteredClient findByClientId(String clientId) throws KnifeOauth2AuthenticationException {

        try {
            // Check if the client is in the cache
            RegisteredClient cachedClient = cachedRegisteredClientsByClientId.get(clientId);
            if (cachedClient != null) {
                return cachedClient;
            }

            // If not in cache, refresh the cache
            cache();
            cachedClient = cachedRegisteredClientsByClientId.get(clientId);
            if (cachedClient != null) {
                return cachedClient;
            }
        } catch (Exception e) {
            flush();
        }


        return knifeClientRepository.findByClientId(clientId)
                .map(this::mapToRegisteredClient)
                .orElseThrow(()->
                        new KnifeOauth2AuthenticationException(ErrorMessages.builder().message("Couldn't find the client ID : " + clientId)
                                .userMessage(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_WRONG_CLIENT_ID_SECRET)).build()));


    }


    private RegisteredClient mapToRegisteredClient(KnifeClient detail) {
        Set<String> scopesSet = Arrays.stream(detail.getScopes().split(","))
                .map(String::trim)
                .collect(Collectors.toSet());

        Set<AuthorizationGrantType> grantTypesSet = Arrays.stream(detail.getAuthorizationGrantTypes().split(","))
                .map(String::trim)
                .map(AuthorizationGrantType::new)
                .collect(Collectors.toSet());

        // Assuming getTokenSettings() returns a map-like structure for token settings.
        Map<String, Object> tokenSettings =  parseMap(detail.getTokenSettings());

        // Extract token time-to-live values from tokenSettings (assuming they are stored as strings or numbers)
        Duration accessTokenTimeToLive = Duration.ofSeconds(Long.parseLong(tokenSettings.get("access_token_time_to_live").toString()));
        Duration refreshTokenTimeToLive = Duration.ofSeconds(Long.parseLong(tokenSettings.get("refresh_token_time_to_live").toString()));


        return RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(detail.getClientId())
                .clientSecret(detail.getClientSecret())
                .clientName(detail.getClientId())
                .clientAuthenticationMethods(authenticationMethods ->
                        authenticationMethods.add(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)) // Adjust based on your entity
                .authorizationGrantTypes(grantTypes -> grantTypes.addAll(grantTypesSet))
                .scopes(scopes -> scopes.addAll(scopesSet))
                .redirectUri("")
                .tokenSettings(TokenSettings.builder()
                        .accessTokenFormat(OAuth2TokenFormat.REFERENCE)
                        .accessTokenTimeToLive(accessTokenTimeToLive)
                        .refreshTokenTimeToLive(refreshTokenTimeToLive)
                        .build())
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build()) // Adjust accordingly
                .build();
    }

    public void cache() {
        List<RegisteredClient> allClients = knifeClientRepository.findAll().stream()
                .map(this::mapToRegisteredClient)
                .toList();
        // Cache all registered clients
        for (RegisteredClient client : allClients) {
            cachedRegisteredClientsByClientId.put(client.getClientId(), client);
        }
    }

    public void flush() {
        cachedRegisteredClientsByClientId = new HashMap<>();
    }

}
