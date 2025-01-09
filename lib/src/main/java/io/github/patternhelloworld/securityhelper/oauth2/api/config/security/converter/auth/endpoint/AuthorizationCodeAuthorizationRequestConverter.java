package io.github.patternhelloworld.securityhelper.oauth2.api.config.security.converter.auth.endpoint;

import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.dao.EasyPlusAuthorizationConsentRepository;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.message.DefaultSecurityUserExceptionMessage;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.message.ISecurityUserExceptionMessageService;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.response.error.dto.EasyPlusErrorMessages;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.response.error.exception.EasyPlusOauth2AuthenticationException;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.serivce.persistence.authorization.OAuth2AuthorizationServiceImpl;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.util.EasyPlusOAuth2EndpointUtils;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.util.ErrorCodeConstants;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import java.util.*;

@RequiredArgsConstructor
public final class AuthorizationCodeAuthorizationRequestConverter implements AuthenticationConverter {

    private final RegisteredClientRepository registeredClientRepository;
    private final EasyPlusAuthorizationConsentRepository easyPlusAuthorizationConsentRepository;
    private final OAuth2AuthorizationServiceImpl oAuth2AuthorizationService;

    private final ISecurityUserExceptionMessageService iSecurityUserExceptionMessageService;


    private static final Authentication ANONYMOUS_AUTHENTICATION = new AnonymousAuthenticationToken("anonymous",
            "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));

    private static final RequestMatcher OIDC_REQUEST_MATCHER = createOidcRequestMatcher();

    /*
     * Why is the validation check done here?
     * - Because if an OAuth2AuthenticationException is thrown in the CustomizedProvider,
     *   Spring retries the process by replacing the CustomizedProvider with the OAuth2AuthorizationCodeRequestAuthenticationProvider.
     *
     * Where is OAuth2AuthorizationCodeRequestAuthenticationToken implemented?
     * - It is handled by "EasyPlusGrantAuthenticationToken" when calling "/oauth2/token"
     */
    @Override
    public Authentication convert(HttpServletRequest request) {

        if (!"GET".equals(request.getMethod()) && !OIDC_REQUEST_MATCHER.matches(request)) {
            throw new EasyPlusOauth2AuthenticationException(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_AUTHORIZATION_CODE_REQUEST_WRONG_METHOD));
        }

        MultiValueMap<String, String> parameters = EasyPlusOAuth2EndpointUtils.getWebParameters(request);

        String clientId = parameters.getFirst(OAuth2ParameterNames.CLIENT_ID);
        if (!StringUtils.hasText(clientId)) {
            throw new EasyPlusOauth2AuthenticationException(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_CLIENT_ID_MISSING));
        }
        String redirectUri = parameters.getFirst(OAuth2ParameterNames.REDIRECT_URI);
        if (!StringUtils.hasText(redirectUri)) {
            throw new EasyPlusOauth2AuthenticationException(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_REDIRECT_URI_MISSING));
        }

        Map<String, Object> additionalParameters = new HashMap<>();

        parameters.forEach((key, value) -> {
            additionalParameters.put(key, (value.size() == 1) ? value.get(0) : value.toArray(new String[0]));
        });


        String state = parameters.getFirst(OAuth2ParameterNames.STATE);
        if (!StringUtils.hasText(state)) {
            throw new EasyPlusOauth2AuthenticationException(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_STATE_MISSING));
        }

        Set<String> requestedScopes = new HashSet<>(parameters.getOrDefault(OAuth2ParameterNames.SCOPE, Collections.emptyList()));

        Authentication principal = SecurityContextHolder.getContext().getAuthentication();
        if (principal == null) {
            setClientAuthenticationContext(clientId);
            principal = SecurityContextHolder.getContext().getAuthentication();
        }

        RegisteredClient registeredClient = ((OAuth2ClientAuthenticationToken) principal).getRegisteredClient();

        if (registeredClient == null) {
            throw new EasyPlusOauth2AuthenticationException(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_REGISTERED_CLIENT_NOT_FOUND));
        }

        if (!registeredClient.getRedirectUris().contains(redirectUri)) {
            throw new EasyPlusOauth2AuthenticationException(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_INVALID_REDIRECT_URI));
        }

        Set<String> registeredScopes = registeredClient.getScopes(); // Scopes from the RegisteredClient

        if (!registeredScopes.containsAll(requestedScopes)) {
            throw new EasyPlusOauth2AuthenticationException(EasyPlusErrorMessages.builder().userMessage(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_INVALID_REDIRECT_URI))
                    .message("Invalid scopes: " + requestedScopes + ". Allowed scopes: " + registeredScopes).build());
        }

        String code = parameters.getFirst(OAuth2ParameterNames.CODE);
        if (!StringUtils.hasText(code)) {
            throw new EasyPlusOauth2AuthenticationException(EasyPlusErrorMessages.builder().userMessage(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_AUTHORIZATION_CODE_MISSING))
                    .errorCode(ErrorCodeConstants.REDIRECT_TO_LOGIN).build());
        }

        return new OAuth2AuthorizationCodeAuthenticationToken(
                code,
                principal,
                redirectUri,
                additionalParameters
        );
    }

    private static RequestMatcher createOidcRequestMatcher() {
        RequestMatcher postMethodMatcher = (request) -> "POST".equals(request.getMethod());
        RequestMatcher responseTypeParameterMatcher = (
                request) -> request.getParameter(OAuth2ParameterNames.RESPONSE_TYPE) != null;
        RequestMatcher openidScopeMatcher = (request) -> {
            String scope = request.getParameter(OAuth2ParameterNames.SCOPE);
            return StringUtils.hasText(scope) && scope.contains(OidcScopes.OPENID);
        };
        return new AndRequestMatcher(postMethodMatcher, responseTypeParameterMatcher, openidScopeMatcher);
    }

    public void setClientAuthenticationContext(String clientId) {
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

}

