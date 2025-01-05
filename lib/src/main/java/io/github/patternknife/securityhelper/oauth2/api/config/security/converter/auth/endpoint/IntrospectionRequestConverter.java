package io.github.patternknife.securityhelper.oauth2.api.config.security.converter.auth.endpoint;

import java.util.HashMap;
import java.util.Map;

import io.github.patternknife.securityhelper.oauth2.api.config.util.KnifeOAuth2EndpointUtils;
import jakarta.servlet.http.HttpServletRequest;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenIntrospectionAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.web.OAuth2TokenIntrospectionEndpointFilter;

import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

/**
 * Attempts to extract an Introspection Request from {@link HttpServletRequest} and then
 * converts it to an {@link OAuth2TokenIntrospectionAuthenticationToken} used for
 * authenticating the request.
 *
 * @author Gerardo Roza
 * @author Joe Grandja
 * @since 0.4.0
 * @see AuthenticationConverter
 * @see OAuth2TokenIntrospectionAuthenticationToken
 * @see OAuth2TokenIntrospectionEndpointFilter
 */
public final class IntrospectionRequestConverter implements AuthenticationConverter {

    /*
    * Now, this only takes "access_token".
    * */
    @Override
    public Authentication convert(HttpServletRequest request) {
        Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();

        MultiValueMap<String, String> parameters = KnifeOAuth2EndpointUtils.getFormParameters(request);

        // token (REQUIRED)
        String token = parameters.getFirst(OAuth2ParameterNames.TOKEN);
        if (!StringUtils.hasText(token) || parameters.get(OAuth2ParameterNames.TOKEN).size() != 1) {
            throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.TOKEN);
        }

        // token_type_hint (OPTIONAL)
        String tokenTypeHint = parameters.getFirst(OAuth2ParameterNames.TOKEN_TYPE_HINT);
        if (StringUtils.hasText(tokenTypeHint) && parameters.get(OAuth2ParameterNames.TOKEN_TYPE_HINT).size() != 1) {
            throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.TOKEN_TYPE_HINT);
        }

        Map<String, Object> additionalParameters = new HashMap<>();
        parameters.forEach((key, value) -> {
            if (!key.equals(OAuth2ParameterNames.TOKEN) && !key.equals(OAuth2ParameterNames.TOKEN_TYPE_HINT)) {
                additionalParameters.put(key, (value.size() == 1) ? value.get(0) : value.toArray(new String[0]));
            }
        });

        return new OAuth2TokenIntrospectionAuthenticationToken(token, clientPrincipal, tokenTypeHint,
                additionalParameters);
    }

    private static void throwError(String errorCode, String parameterName) {
        OAuth2Error error = new OAuth2Error(errorCode, "OAuth 2.0 Token Introspection Parameter: " + parameterName,
                "https://datatracker.ietf.org/doc/html/rfc7662#section-2.1");
        throw new OAuth2AuthenticationException(error);
    }

}
