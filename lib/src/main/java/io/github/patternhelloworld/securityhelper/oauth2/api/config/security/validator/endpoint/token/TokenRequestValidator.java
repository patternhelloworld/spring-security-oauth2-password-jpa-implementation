package io.github.patternhelloworld.securityhelper.oauth2.api.config.security.validator.endpoint.token;

import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.message.DefaultSecurityUserExceptionMessage;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.message.ISecurityUserExceptionMessageService;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.response.error.dto.EasyPlusErrorMessages;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.response.error.exception.EasyPlusOauth2AuthenticationException;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.serivce.persistence.client.CacheableRegisteredClientRepositoryImpl;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.validator.endpoint.AbstractEasyPlusBaseValidator;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.util.EasyPlusErrorCodeConstants;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.util.Arrays;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;


public class TokenRequestValidator extends AbstractEasyPlusBaseValidator implements Function<Map<String, Object>, CodeValidationResult> {

    private final CacheableRegisteredClientRepositoryImpl cacheableRegisteredClientRepository;
    private final ISecurityUserExceptionMessageService iSecurityUserExceptionMessageService;

    public TokenRequestValidator(CacheableRegisteredClientRepositoryImpl cacheableRegisteredClientRepository, ISecurityUserExceptionMessageService iSecurityUserExceptionMessageService) {
        super(iSecurityUserExceptionMessageService);
        this.cacheableRegisteredClientRepository = cacheableRegisteredClientRepository;
        this.iSecurityUserExceptionMessageService = iSecurityUserExceptionMessageService;
    }

    @Override
    public CodeValidationResult apply(Map<String, Object> additionalParameters) {

        String clientId = validateClientIdForTokenRequest(additionalParameters);

        // The grant_type has already been parsed by ClientSecretBasicAuthenticationConverter.
        // Therefore, there is no need to validate the grant_type itself again at this point.
        String grantType = additionalParameters.get("grant_type").toString();
        // However, the necessary parameters for the grant_type have not been checked.
        switch (grantType) {
            case "authorization_code" -> {
                if(additionalParameters.get("code") == null) {
                    throw new EasyPlusOauth2AuthenticationException(EasyPlusErrorMessages.builder().errorCode(EasyPlusErrorCodeConstants.MISSING_AUTHORIZATION_CODE).message("No code found for the grant type " + grantType).userMessage(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_LOGIN_ERROR)).build());
                }
            }
            case "password" -> {
                if(additionalParameters.get("username") == null) {
                    throw new EasyPlusOauth2AuthenticationException(EasyPlusErrorMessages.builder().errorCode(EasyPlusErrorCodeConstants.MISSING_USERNAME).message("No username found for the grant type " + grantType).userMessage(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_LOGIN_ERROR)).build());
                }
                if(additionalParameters.get("password") == null) {
                    throw new EasyPlusOauth2AuthenticationException(EasyPlusErrorMessages.builder().errorCode(EasyPlusErrorCodeConstants.MISSING_PASSWORD).message("No password found for the grant type " + grantType).userMessage(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_LOGIN_ERROR)).build());
                }
            }
            case "refresh_token" -> {
                if(additionalParameters.get("refresh_token") == null) {
                    throw new EasyPlusOauth2AuthenticationException(EasyPlusErrorMessages.builder().errorCode(EasyPlusErrorCodeConstants.MISSING_REFRESH_TOKEN).message("No refresh_token found for the grant type " + grantType).userMessage(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_LOGIN_ERROR)).build());
                }
            }
            default -> throw new EasyPlusOauth2AuthenticationException(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_WRONG_GRANT_TYPE));
        }

        RegisteredClient registeredClient = cacheableRegisteredClientRepository.findByClientId(clientId.toString());
        if (registeredClient == null) {
            throw new EasyPlusOauth2AuthenticationException(EasyPlusErrorMessages.builder().message("client_id NOT found in DB").userMessage(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_LOGIN_ERROR)).build());
        }
        Set<String> registeredScopes = registeredClient.getScopes();
        Set<String> requestedScopes = Arrays.stream(
                        additionalParameters.getOrDefault(OAuth2ParameterNames.SCOPE, "")
                                .toString()
                                .split(",")
                )
                .map(String::trim)
                .filter(scope -> !scope.isEmpty())
                .collect(Collectors.toSet());
        if (!registeredScopes.containsAll(requestedScopes)) {
            throw new EasyPlusOauth2AuthenticationException(EasyPlusErrorMessages.builder().userMessage(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_LOGIN_ERROR))
                    .errorCode(EasyPlusErrorCodeConstants.SCOPE_MISMATCH).message("Invalid scopes: " + requestedScopes + ". Allowed scopes: " + registeredScopes).build());
        }

        return CodeValidationResult.builder()
                .clientId(clientId)
                .grantType(grantType)
                .code(getNullableParameter(additionalParameters, "code"))
                .username(getNullableParameter(additionalParameters, "username"))
                .password(getNullableParameter(additionalParameters, "password"))
                .refreshToken(getNullableParameter(additionalParameters, "refresh_token"))
                .registeredClient(registeredClient)
                .responseType(getNullableParameter(additionalParameters, "response_type"))
                .build();

    }
}
