package io.github.patternknife.securityhelper.oauth2.api.config.security.converter.auth.endpoint;

import io.github.patternknife.securityhelper.oauth2.api.config.util.RequestOAuth2Distiller;
import io.github.patternknife.securityhelper.oauth2.api.config.security.token.CustomGrantAuthenticationToken;
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
public final class PasswordAuthenticationConverter implements AuthenticationConverter {
    /*
    *   `
    *      CustomGrantAuthenticationToken <- OAuth2ClientAuthenticationToken
    *
    * */
    @Override
    public Authentication convert(HttpServletRequest request) {

        OAuth2ClientAuthenticationToken oAuth2ClientAuthenticationToken = (OAuth2ClientAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();

        Map<String, Object> additionalParameters = RequestOAuth2Distiller.getTokenUsingSecurityAdditionalParameters(request);

        OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
                .clientId((String) additionalParameters.get(OAuth2ParameterNames.CLIENT_ID))
                .authorizationUri("http://localhost:8081/callback1")
                .redirectUri("http://localhost:8081/callback1")// 스코프 설정
                .state("aaa")
                .build();
        additionalParameters.put(OAuth2AuthorizationRequest.class.getName(), authorizationRequest);


        CustomGrantAuthenticationToken customGrantAuthenticationToken = new CustomGrantAuthenticationToken(new AuthorizationGrantType((String) additionalParameters.get("grant_type")),
                oAuth2ClientAuthenticationToken, additionalParameters);
        additionalParameters.put(Principal.class.getName(), customGrantAuthenticationToken);

        return customGrantAuthenticationToken;
    }

}
