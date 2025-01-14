package io.github.patternhelloworld.securityhelper.oauth2.api.config.security.converter.auth.endpoint;

import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.dao.EasyPlusAuthorizationConsentRepository;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.entity.EasyPlusAuthorizationConsent;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.message.DefaultSecurityUserExceptionMessage;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.message.ISecurityUserExceptionMessageService;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.response.error.dto.EasyPlusErrorMessages;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.response.error.exception.EasyPlusOauth2AuthenticationException;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.serivce.persistence.authorization.OAuth2AuthorizationServiceImpl;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.validator.endpoint.authorization.CodeValidationResult;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.util.EasyPlusErrorCodeConstants;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.util.EasyPlusOAuth2EndpointUtils;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpMethod;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import java.util.Map;
import java.util.function.Function;

@RequiredArgsConstructor
public final class CodeAuthorizationConditionalConverter implements AuthenticationConverter {

    private Function<MultiValueMap<String, String>, CodeValidationResult> authenticationValidator;

    private final EasyPlusAuthorizationConsentRepository easyPlusAuthorizationConsentRepository;
    private final OAuth2AuthorizationServiceImpl oAuth2AuthorizationService;

    private final ISecurityUserExceptionMessageService iSecurityUserExceptionMessageService;

    private final String consentYN;

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

        MultiValueMap<String, String> parameters = EasyPlusOAuth2EndpointUtils.getWebParametersContainingEasyPlusHeaders(request);

        CodeValidationResult codeValidationResult = this.authenticationValidator.apply(parameters);

        Map<String, Object> additionalParameters = EasyPlusOAuth2EndpointUtils.convertMultiValueMapToMap(parameters);

        Authentication principal = SecurityContextHolder.getContext().getAuthentication();
        if (principal == null) {
            setClientAuthenticationContext(codeValidationResult.getRegisteredClient());
            principal = SecurityContextHolder.getContext().getAuthentication();
        }

        String code = parameters.getFirst(OAuth2ParameterNames.CODE);
        if (!StringUtils.hasText(code)) {
            return new OAuth2AuthorizationCodeRequestAuthenticationToken(request.getRequestURL().toString(), codeValidationResult.getClientId(), principal, codeValidationResult.getRedirectUri(), codeValidationResult.getState(), codeValidationResult.getScope(), additionalParameters);
        }

        // Check Consent
        if(consentYN.equals("Y")) {
            OAuth2Authorization oAuth2Authorization = oAuth2AuthorizationService.findByToken(code, new OAuth2TokenType(OAuth2ParameterNames.CODE));
            EasyPlusAuthorizationConsent easyPlusAuthorizationConsent = easyPlusAuthorizationConsentRepository.findByRegisteredClientIdAndPrincipalName(oAuth2Authorization.getRegisteredClientId(), oAuth2Authorization.getPrincipalName()).orElse(null);
            if (easyPlusAuthorizationConsent == null) {
                if (request.getMethod().equals(HttpMethod.POST.toString())) {
                    // This means the user checks authorization consent OK
                    easyPlusAuthorizationConsent = new EasyPlusAuthorizationConsent();
                    easyPlusAuthorizationConsent.setPrincipalName(oAuth2Authorization.getPrincipalName());
                    easyPlusAuthorizationConsent.setRegisteredClientId(oAuth2Authorization.getRegisteredClientId());
                    easyPlusAuthorizationConsent.setAuthorities(oAuth2Authorization.getAuthorizedScopes().stream().reduce((scope1, scope2) -> scope1 + "," + scope2).orElse(""));
                    easyPlusAuthorizationConsentRepository.save(easyPlusAuthorizationConsent);
                } else {
                    // This means the user should check authorization consent OK
                    throw new EasyPlusOauth2AuthenticationException(EasyPlusErrorMessages.builder().userMessage(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_AUTHORIZATION_CODE_MISSING))
                            .errorCode(EasyPlusErrorCodeConstants.REDIRECT_TO_CONSENT).build());
                }
            }
        }

        return new OAuth2AuthorizationCodeAuthenticationToken(
                code,
                principal,
                codeValidationResult.getRedirectUri(),
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

    public void setClientAuthenticationContext(RegisteredClient registeredClient) {
        OAuth2ClientAuthenticationToken clientAuthenticationToken = new OAuth2ClientAuthenticationToken(
                registeredClient,
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                null
        );

        SecurityContextHolder.getContext().setAuthentication(clientAuthenticationToken);
    }

    public void setAuthenticationValidator(Function<MultiValueMap<String, String>, CodeValidationResult> authenticationValidator) {
        Assert.notNull(authenticationValidator, "authenticationValidator cannot be null");
        this.authenticationValidator = authenticationValidator;
    }
}

