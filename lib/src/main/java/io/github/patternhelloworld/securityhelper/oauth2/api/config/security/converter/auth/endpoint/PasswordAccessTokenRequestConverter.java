package io.github.patternhelloworld.securityhelper.oauth2.api.config.security.converter.auth.endpoint;

import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.token.EasyPlusGrantAuthenticationToken;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.util.EasyPlusOAuth2EndpointUtils;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationConverter;

import java.util.Map;

@RequiredArgsConstructor
public final class PasswordAccessTokenRequestConverter implements AuthenticationConverter {
    /*
    *   `
    *      EasyPlusGrantAuthenticationToken <- OAuth2ClientAuthenticationToken
    *
    * */
    @Override
    public Authentication convert(HttpServletRequest request) {

        OAuth2ClientAuthenticationToken oAuth2ClientAuthenticationToken = (OAuth2ClientAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();

        Map<String, Object> additionalParameters = EasyPlusOAuth2EndpointUtils.getApiParameters(request);

        //  additionalParameters.put(Principal.class.getName(), easyPlusGrantAuthenticationToken);

        return new EasyPlusGrantAuthenticationToken(new AuthorizationGrantType((String) additionalParameters.get("grant_type")),
                oAuth2ClientAuthenticationToken, additionalParameters);
    }

}
