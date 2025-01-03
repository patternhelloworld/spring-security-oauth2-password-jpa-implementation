package io.github.patternknife.securityhelper.oauth2.api.config.security.converter.auth.endpoint;

import io.github.patternknife.securityhelper.oauth2.api.config.security.dao.KnifeAuthorizationConsentRepository;
import io.github.patternknife.securityhelper.oauth2.api.config.security.response.error.exception.KnifeOauth2AuthenticationException;
import io.github.patternknife.securityhelper.oauth2.api.config.security.serivce.persistence.authorization.OAuth2AuthorizationServiceImpl;
import io.github.patternknife.securityhelper.oauth2.api.config.util.RequestOAuth2Distiller;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import java.util.*;

@RequiredArgsConstructor
public final class AuthorizationCodeRequestAuthenticationConverter implements AuthenticationConverter {

    private final RegisteredClientRepository registeredClientRepository;
    private final KnifeAuthorizationConsentRepository knifeAuthorizationConsentRepository;
    private final OAuth2AuthorizationServiceImpl oAuth2AuthorizationService;

    public void setClientAuthentication(String clientId) {
        RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);
        if (registeredClient == null) {
            throw new IllegalArgumentException("Invalid client ID");
        }

        OAuth2ClientAuthenticationToken clientAuthenticationToken = new OAuth2ClientAuthenticationToken(
                registeredClient,
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                null
        );

        SecurityContextHolder.getContext().setAuthentication(clientAuthenticationToken);
    }

    @Override
    @Nullable
    public Authentication convert(HttpServletRequest request) {
        if ("POST".equalsIgnoreCase(request.getMethod())) {
            // TODO:  Authorization Consent
        } else if ("GET".equalsIgnoreCase(request.getMethod())) {
            MultiValueMap<String, String> parameters = RequestOAuth2Distiller.getAuthorizationCodeSecurityAdditionalParameters(request);
            String code = parameters.getFirst(OAuth2ParameterNames.CODE);

            if (!StringUtils.hasText(code)) {
                throw new KnifeOauth2AuthenticationException("Authorization code missing in GET request");
            }

            // 클라이언트 ID와 기타 필수 파라미터 처리
            String clientId = parameters.getFirst(OAuth2ParameterNames.CLIENT_ID);
            if (!StringUtils.hasText(clientId)) {
                throw new KnifeOauth2AuthenticationException("client_id missing");
            }

            // 클라이언트 인증 설정
            setClientAuthentication(clientId);
            Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();

            String redirectUri = parameters.getFirst(OAuth2ParameterNames.REDIRECT_URI);
            if (!StringUtils.hasText(redirectUri)) {
                throw new KnifeOauth2AuthenticationException("redirect_uri missing");
            }


            RegisteredClient registeredClient = ((OAuth2ClientAuthenticationToken) clientPrincipal).getRegisteredClient();

            // Check if the registered client is null
            if (registeredClient == null) {
                throw new KnifeOauth2AuthenticationException("Registered client is missing or invalid");
            }
            // Check if the redirectUri is not in the registered redirect URIs
            if (!registeredClient.getRedirectUris().contains(redirectUri)) {
                throw new KnifeOauth2AuthenticationException("Invalid redirect_uri: " + redirectUri);
            }


            Set<String> requestedScopes = new HashSet<>(parameters.getOrDefault(OAuth2ParameterNames.SCOPE, Collections.emptyList()));
             // Scopes from the request
            Set<String> registeredScopes = registeredClient.getScopes(); // Scopes from the RegisteredClient

            if (!registeredScopes.containsAll(requestedScopes)) {
                throw new KnifeOauth2AuthenticationException("Invalid scopes: " + requestedScopes + ". Allowed scopes: " + registeredScopes);
            }

            Map<String, Object> additionalParameters = new HashMap<>();

            parameters.forEach((key, value) -> {
                additionalParameters.put(key, (value.size() == 1) ? value.get(0) : value.toArray(new String[0]));
            });

            return new OAuth2AuthorizationCodeAuthenticationToken(
                    code,
                    clientPrincipal,
                    redirectUri,
                    additionalParameters
            );

        } else {
            throw new IllegalStateException("Unsupported HTTP method: " + request.getMethod());
        }

        return null;
        // TODO:  Authorization Consent
        /*        return new OAuth2AuthorizationCodeRequestAuthenticationToken(
                parameters.getFirst(OAuth2ParameterNames.REDIRECT_URI),
                clientId,
                clientPrincipal,
                redirectUri,
                state,
                scopes,
                additionalParameters
        );*/
    }
}

