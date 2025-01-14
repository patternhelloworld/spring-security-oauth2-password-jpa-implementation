package io.github.patternhelloworld.securityhelper.oauth2.api.config.security.validator.endpoint.authorization;

import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.message.DefaultSecurityUserExceptionMessage;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.message.ISecurityUserExceptionMessageService;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.response.error.dto.EasyPlusErrorMessages;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.response.error.exception.EasyPlusOauth2AuthenticationException;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.serivce.persistence.client.CacheableRegisteredClientRepositoryImpl;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.validator.endpoint.AbstractEasyPlusBaseValidator;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.util.EasyPlusErrorCodeConstants;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Function;


public class CodeRequestValidator extends AbstractEasyPlusBaseValidator implements Function<MultiValueMap<String, String>, CodeValidationResult> {

    private final CacheableRegisteredClientRepositoryImpl cacheableRegisteredClientRepository;
    private final ISecurityUserExceptionMessageService iSecurityUserExceptionMessageService;

    public CodeRequestValidator(CacheableRegisteredClientRepositoryImpl cacheableRegisteredClientRepository, ISecurityUserExceptionMessageService iSecurityUserExceptionMessageService) {
        super(iSecurityUserExceptionMessageService);
        this.cacheableRegisteredClientRepository = cacheableRegisteredClientRepository;
        this.iSecurityUserExceptionMessageService = iSecurityUserExceptionMessageService;
    }

    @Override
    public CodeValidationResult apply(MultiValueMap<String, String> queryParameters) {

        String clientId = validateClientIdForCodeRequest(queryParameters);

        String redirectUri = queryParameters.getFirst(OAuth2ParameterNames.REDIRECT_URI);
        if (!StringUtils.hasText(redirectUri)) {
            throw new EasyPlusOauth2AuthenticationException(EasyPlusErrorMessages.builder().errorCode(EasyPlusErrorCodeConstants.MISSING_REDIRECT_URI).message(EasyPlusErrorCodeConstants.MISSING_REDIRECT_URI).userMessage(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_LOGIN_ERROR)).build());
        }
        String state = queryParameters.getFirst(OAuth2ParameterNames.STATE);
        if (!StringUtils.hasText(state)) {
            throw new EasyPlusOauth2AuthenticationException(EasyPlusErrorMessages.builder().errorCode(EasyPlusErrorCodeConstants.MISSING_STATE).message(EasyPlusErrorCodeConstants.MISSING_STATE).userMessage(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_LOGIN_ERROR)).build());
        }


        RegisteredClient registeredClient = cacheableRegisteredClientRepository.findByClientId(clientId);
        if (registeredClient == null) {
            throw new EasyPlusOauth2AuthenticationException(EasyPlusErrorMessages.builder().message("client_id NOT found in DB").userMessage(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_LOGIN_ERROR)).build());
        }
        Set<String> registeredScopes = registeredClient.getScopes();
        Set<String> requestedScopes = new HashSet<>(queryParameters.getOrDefault(OAuth2ParameterNames.SCOPE, Collections.emptyList()));
        if (!registeredScopes.containsAll(requestedScopes)) {
            throw new EasyPlusOauth2AuthenticationException(EasyPlusErrorMessages.builder().userMessage(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_LOGIN_ERROR))
                    .errorCode(EasyPlusErrorCodeConstants.SCOPE_MISMATCH).message("Invalid scopes: " + requestedScopes + ". Allowed scopes: " + registeredScopes).build());
        }

        return CodeValidationResult.builder()
                .clientId(clientId)
                .redirectUri(redirectUri)
                .state(state)
                .scope(registeredScopes)
                .registeredClient(registeredClient)
                .build();
    }
}
