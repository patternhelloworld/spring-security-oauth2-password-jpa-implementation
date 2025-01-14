package io.github.patternhelloworld.securityhelper.oauth2.api.config.security.validator.endpoint;

import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.message.DefaultSecurityUserExceptionMessage;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.message.ISecurityUserExceptionMessageService;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.response.error.dto.EasyPlusErrorMessages;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.response.error.exception.EasyPlusOauth2AuthenticationException;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.util.EasyPlusErrorCodeConstants;
import lombok.RequiredArgsConstructor;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

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
    protected String validateClientIdForTokenRequest(Map<String, Object> additionalParameters) {
        Object clientIdObj = additionalParameters.get("client_id");
        if (clientIdObj == null) {
            throw new EasyPlusOauth2AuthenticationException(
                    EasyPlusErrorMessages.builder().errorCode(EasyPlusErrorCodeConstants.MISSING_CLIENT_ID)
                            .message("Invalid Request. As the token request has been processed by 'ClientSecretBasicAuthenticationConverter', this can be issues with 1) Missing client ID, 2) Wrong Client Secret, 3) Authorization Code Expired, 4) PKCE Parameter Error.")
                            .userMessage(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_LOGIN_ERROR))
                            .build()
            );
        }
        return clientIdObj.toString();
    }

    protected String validateClientIdForCodeRequest(MultiValueMap<String, String> additionalParameters) {
        String clientId = additionalParameters.getFirst("client_id");
        if (!StringUtils.hasText(clientId)) {
            throw new EasyPlusOauth2AuthenticationException(
                    EasyPlusErrorMessages.builder().errorCode(EasyPlusErrorCodeConstants.MISSING_CLIENT_ID)
                            .message("Invalid Request. Missing client_id.")
                            .userMessage(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_LOGIN_ERROR))
                            .build()
            );
        }
        return clientId;
    }

    protected String getNullableParameter(Map<String, Object> parameters, String key) {
        Object value = parameters.get(key);
        return value != null ? value.toString() : null;
    }
}
