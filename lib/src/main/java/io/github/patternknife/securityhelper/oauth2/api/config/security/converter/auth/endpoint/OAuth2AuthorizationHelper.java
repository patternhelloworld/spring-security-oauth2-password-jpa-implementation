package io.github.patternknife.securityhelper.oauth2.api.config.security.converter.auth.endpoint;

import io.github.patternknife.securityhelper.oauth2.api.config.security.dao.KnifeAuthorizationConsentRepository;
import io.github.patternknife.securityhelper.oauth2.api.config.security.entity.KnifeAuthorizationConsent;
import io.github.patternknife.securityhelper.oauth2.api.config.security.response.error.exception.KnifeOauth2AuthenticationException;
import io.github.patternknife.securityhelper.oauth2.api.config.security.serivce.persistence.authorization.OAuth2AuthorizationServiceImpl;
import io.github.patternknife.securityhelper.oauth2.api.config.security.serivce.persistence.client.RegisteredClientRepositoryImpl;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.util.Optional;

public class OAuth2AuthorizationHelper {

    public static OAuth2Authorization validateAndGetAuthorization(
            String authorizationCode,
            String responseType,
            String clientId,
            String redirectUri,
            String scope,
            RegisteredClientRepository registeredClientRepository,
            OAuth2AuthorizationServiceImpl oAuth2AuthorizationService,
            KnifeAuthorizationConsentRepository authorizationConsentRepository) {

        if (authorizationCode == null) {
            throw new KnifeOauth2AuthenticationException("Authorization code is missing");
        }

        if (!"code".equals(responseType)) {
            throw new KnifeOauth2AuthenticationException("Invalid response type");
        }

        RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);
        if (registeredClient == null) {
            throw new KnifeOauth2AuthenticationException("Invalid client ID");
        }

/*
        if (!registeredClient.getRedirectUris().contains(redirectUri)) {
            throw new KnifeOauth2AuthenticationException("Invalid redirect URI");
        }
*/

        OAuth2Authorization oAuth2Authorization = oAuth2AuthorizationService.findByToken(authorizationCode, new OAuth2TokenType("authorization_code"));
        if (oAuth2Authorization == null) {
            throw new KnifeOauth2AuthenticationException("Authorization not found");
        }

/*        Optional<KnifeAuthorizationConsent> currentAuthorizationConsent =
                authorizationConsentRepository.findByRegisteredClientIdAndPrincipalName(registeredClient.getId(), oAuth2Authorization.getPrincipalName());
        if (currentAuthorizationConsent != null) {
            throw new KnifeOauth2AuthenticationException("Consent already given");
        }*/

        return oAuth2Authorization;
    }
}
