package io.github.patternhelloworld.securityhelper.oauth2.api.config.security.validator.endpoint;

import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.message.DefaultSecurityUserExceptionMessage;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.message.ISecurityUserExceptionMessageService;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.response.error.dto.EasyPlusErrorMessages;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.response.error.exception.EasyPlusOauth2AuthenticationException;
import lombok.RequiredArgsConstructor;

import java.util.Map;

@RequiredArgsConstructor
public abstract class AbstractEasyPlusBaseValidator {

    private final ISecurityUserExceptionMessageService iSecurityUserExceptionMessageService;

    /**
     * Validates the client_id and returns it as a String.
     *
     * <p>This method ensures that the client_id is present and valid in the given request parameters.
     * If the client_id is missing or invalid, an {@link EasyPlusOauth2AuthenticationException} is thrown.</p>
     *
     * @param additionalParameters the request parameters containing the client_id
     * @return the validated client_id as a String
     * @throws EasyPlusOauth2AuthenticationException if client_id is missing or invalid
     *
     * <p><b>Note (only for TokenRequests):</b> If an incorrect client ID or secret is provided,
     * the {@code OpaqueGrantTypeAccessTokenRequestConverter} will not be invoked because
     * the {@code ClientSecretBasicAuthenticationConverter} returns {@code null}.
     * This means the mandatory client_id header parameter is not added in the {@code OpaqueGrantTypeAccessTokenRequestConverter}.
     * </p>
     *
     * <p>For reference, if an incorrect Basic header, such as {@code base64(client_id:<--no secret here-->)} is detected,
     * the {@code ClientSecretBasicAuthenticationConverter} handles it directly and delegates to the {@code AuthenticationFailureHandler}.
     * </p>
     */
    protected String validateClientId(Map<String, Object> additionalParameters) {
        Object clientIdObj = additionalParameters.get("client_id");
        if (clientIdObj == null) {
            throw new EasyPlusOauth2AuthenticationException(
                    EasyPlusErrorMessages.builder()
                            .message("Invalid Request. Missing client_id.")
                            .userMessage(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_LOGIN_ERROR))
                            .build()
            );
        }
        return clientIdObj.toString();
    }

    protected String getNullableParameter(Map<String, Object> parameters, String key) {
        Object value = parameters.get(key);
        return value != null ? value.toString() : null;
    }
}
