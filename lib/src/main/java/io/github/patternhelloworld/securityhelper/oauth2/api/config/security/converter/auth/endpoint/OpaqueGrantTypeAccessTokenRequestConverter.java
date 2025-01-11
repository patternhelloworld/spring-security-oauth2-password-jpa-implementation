package io.github.patternhelloworld.securityhelper.oauth2.api.config.security.converter.auth.endpoint;

import io.github.patternhelloworld.securityhelper.oauth2.api.config.util.EasyPlusOAuth2EndpointUtils;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationConverter;

import java.util.Map;

@RequiredArgsConstructor
public final class OpaqueGrantTypeAccessTokenRequestConverter implements AuthenticationConverter {

    @Override
    public Authentication convert(HttpServletRequest request) {

        Map<String, Object> allParameters = EasyPlusOAuth2EndpointUtils.getApiParametersContainingEasyPlusHeaders(request);

        String clientId = allParameters.get("client_id").toString();

        // All token requests are "CLIENT_SECRET_BASIC"
        ClientAuthenticationMethod clientAuthenticationMethod = ClientAuthenticationMethod.CLIENT_SECRET_BASIC;
        Object credentials = null;

        OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
                .clientId(clientId)
                .authorizationUri(request.getRequestURL().toString())
                .additionalParameters(allParameters)
                .build();

        allParameters.put(OAuth2AuthorizationRequest.class.getName(), authorizationRequest);

        return new OAuth2ClientAuthenticationToken(
                clientId,
                clientAuthenticationMethod,
                credentials,
                allParameters
        );
    }



}
