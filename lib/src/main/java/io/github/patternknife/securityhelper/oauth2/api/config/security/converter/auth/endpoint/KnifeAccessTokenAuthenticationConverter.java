package io.github.patternknife.securityhelper.oauth2.api.config.security.converter.auth.endpoint;

import io.github.patternknife.securityhelper.oauth2.api.config.util.RequestOAuth2Distiller;
import io.github.patternknife.securityhelper.oauth2.api.config.security.token.KnifeGrantAuthenticationToken;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationConverter;

import java.security.Principal;
import java.util.Map;

@RequiredArgsConstructor
public final class KnifeAccessTokenAuthenticationConverter implements AuthenticationConverter {
    /*
    *   `
    *      CustomGrantAuthenticationToken <- OAuth2ClientAuthenticationToken
    *
    * */
    @Override
    public Authentication convert(HttpServletRequest request) {

        OAuth2ClientAuthenticationToken oAuth2ClientAuthenticationToken = (OAuth2ClientAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();

        Map<String, Object> additionalParameters = RequestOAuth2Distiller.getTokenUsingSecurityAdditionalParameters(request);


        KnifeGrantAuthenticationToken knifeGrantAuthenticationToken = new KnifeGrantAuthenticationToken(new AuthorizationGrantType((String) additionalParameters.get("grant_type")),
                oAuth2ClientAuthenticationToken, additionalParameters);
        additionalParameters.put(Principal.class.getName(), knifeGrantAuthenticationToken);

        return knifeGrantAuthenticationToken;
    }

}
