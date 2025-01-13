package io.github.patternhelloworld.securityhelper.oauth2.api.config.security.serivce.persistence.client;


import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.dao.EasyPlusClientRepository;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.entity.EasyPlusClient;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.message.DefaultSecurityUserExceptionMessage;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.message.ISecurityUserExceptionMessageService;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.response.error.dto.EasyPlusErrorMessages;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.response.error.exception.EasyPlusOauth2AuthenticationException;
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
public class CacheableRegisteredClientRepositoryImpl implements RegisteredClientRepository {

    private Map<String, @NotNull RegisteredClient> cachedRegisteredClientsByClientId = new HashMap<>();

    private final EasyPlusClientRepository easyPlusClientRepository;
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

        EasyPlusClient easyPlusClient = new EasyPlusClient();

        easyPlusClient.setId(UUID.randomUUID().toString());
        easyPlusClient.setClientId(registeredClient.getClientId());
        easyPlusClient.setClientSecret(registeredClient.getClientSecret());
        easyPlusClient.setScopes(String.join(",", registeredClient.getScopes()));

        String grantTypes = registeredClient.getAuthorizationGrantTypes().stream()
                .map(AuthorizationGrantType::getValue)
                .collect(Collectors.joining(","));
        easyPlusClient.setAuthorizationGrantTypes(grantTypes);

        // Parse and set Client Settings
        String clientSettingsJson = writeMap(registeredClient.getClientSettings().getSettings());
        easyPlusClient.setClientSettings(clientSettingsJson);

        // Parse and set Token Settings
        String tokenSettingsJson = writeMap(registeredClient.getTokenSettings().getSettings());
        easyPlusClient.setTokenSettings(tokenSettingsJson);

        easyPlusClientRepository.save(easyPlusClient);

        // Cache the registered client as long as the persistence logic above is successful.
        cachedRegisteredClientsByClientId.put(registeredClient.getClientId(), registeredClient);
    }

    @Override
    public @NotNull RegisteredClient findById(String id) throws EasyPlusOauth2AuthenticationException {
        return easyPlusClientRepository.findById(id)
                .map(this::mapToRegisteredClient)
                .orElseThrow(()->
                        new EasyPlusOauth2AuthenticationException(EasyPlusErrorMessages.builder().message("Couldn't find the ID : " + id)
                                .userMessage(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_WRONG_CLIENT_ID_SECRET)).build()));
    }
    @Override
    public @NotNull RegisteredClient findByClientId(String clientId) throws EasyPlusOauth2AuthenticationException {

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


        return easyPlusClientRepository.findByClientId(clientId)
                .map(this::mapToRegisteredClient)
                .orElseThrow(()->
                        new EasyPlusOauth2AuthenticationException(EasyPlusErrorMessages.builder().message("Couldn't find the client ID : " + clientId)
                                .userMessage(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_WRONG_CLIENT_ID_SECRET)).build()));


    }


    private RegisteredClient mapToRegisteredClient(EasyPlusClient easyPlusClient) {
        Set<String> scopesSet = Arrays.stream(easyPlusClient.getScopes().split(","))
                .map(String::trim)
                .collect(Collectors.toSet());

        Set<AuthorizationGrantType> grantTypesSet = Arrays.stream(easyPlusClient.getAuthorizationGrantTypes().split(","))
                .map(String::trim)
                .map(AuthorizationGrantType::new)
                .collect(Collectors.toSet());

        // Assuming getTokenSettings() returns a map-like structure for token settings.
        Map<String, Object> tokenSettings =  parseMap(easyPlusClient.getTokenSettings());

        // Extract token time-to-live values from tokenSettings (assuming they are stored as strings or numbers)
        Duration accessTokenTimeToLive = Duration.ofSeconds(Long.parseLong(tokenSettings.get("access_token_time_to_live").toString()));
        Duration refreshTokenTimeToLive = Duration.ofSeconds(Long.parseLong(tokenSettings.get("refresh_token_time_to_live").toString()));


        return RegisteredClient.withId(easyPlusClient.getId())
                .clientId(easyPlusClient.getClientId())
                .clientSecret(easyPlusClient.getClientSecret())
                .clientName(easyPlusClient.getClientId())
                .clientAuthenticationMethods(authenticationMethods ->
                        authenticationMethods.add(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)) // Adjust based on your entity
                .authorizationGrantTypes(grantTypes -> grantTypes.addAll(grantTypesSet))
                .scopes(scopes -> scopes.addAll(scopesSet))
                .redirectUri(easyPlusClient.getRedirectUris())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                        .accessTokenTimeToLive(accessTokenTimeToLive)
                        .refreshTokenTimeToLive(refreshTokenTimeToLive)
                        .build())
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build()) // Adjust accordingly
                .build();
    }

    public void cache() {
        List<RegisteredClient> allClients = easyPlusClientRepository.findAll().stream()
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
