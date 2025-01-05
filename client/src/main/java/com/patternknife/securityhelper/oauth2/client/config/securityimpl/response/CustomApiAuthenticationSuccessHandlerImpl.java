package com.patternknife.securityhelper.oauth2.client.config.securityimpl.response;


import io.github.patternknife.securityhelper.oauth2.api.config.security.message.DefaultSecurityUserExceptionMessage;
import io.github.patternknife.securityhelper.oauth2.api.config.security.message.ISecurityUserExceptionMessageService;
import io.github.patternknife.securityhelper.oauth2.api.config.security.response.error.dto.KnifeErrorMessages;
import io.github.patternknife.securityhelper.oauth2.api.config.security.response.error.exception.KnifeOauth2AuthenticationException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;

/*
 *
 * The functionality is already implemented in the library's
 * 'io.github.patternknife.securityhelper.oauth2.api.config.security.response.auth.authentication.DefaultAuthenticationSuccessHandlerImpl'.
 *
 * Create this class only if you need a custom implementation that differs from the default.
 */
@Primary
@Qualifier("apiAuthenticationSuccessHandler")
@Configuration
@RequiredArgsConstructor
public class CustomApiAuthenticationSuccessHandlerImpl implements AuthenticationSuccessHandler {

    private final HttpMessageConverter<OAuth2AccessTokenResponse> accessTokenHttpResponseConverter =
            new OAuth2AccessTokenResponseHttpMessageConverter();


    private final ISecurityUserExceptionMessageService iSecurityUserExceptionMessageService;

    @Override
    public void onAuthenticationSuccess(final HttpServletRequest request, final HttpServletResponse response, final Authentication authentication) throws IOException {

        final OAuth2AccessTokenAuthenticationToken accessTokenAuthentication = (OAuth2AccessTokenAuthenticationToken) authentication;

        OAuth2AccessToken accessToken = accessTokenAuthentication.getAccessToken();
        OAuth2RefreshToken refreshToken = accessTokenAuthentication.getRefreshToken();
        Map<String, Object> additionalParameters = accessTokenAuthentication.getAdditionalParameters();

        if (((String) additionalParameters.get("grant_type")).equals(AuthorizationGrantType.PASSWORD.getValue())
          || ((String) additionalParameters.get("grant_type")).equals(OAuth2ParameterNames.CODE)) {
            OAuth2AccessTokenResponse.Builder builder = OAuth2AccessTokenResponse.withToken(accessToken.getTokenValue())
                    .tokenType(accessToken.getTokenType())
                    .scopes(accessToken.getScopes());
            if (accessToken.getExpiresAt() != null) {
                builder.expiresIn(ChronoUnit.SECONDS.between(Instant.now(), accessToken.getExpiresAt()));
            }
            if (refreshToken != null) {
                builder.refreshToken(refreshToken.getTokenValue());
            }
            OAuth2AccessTokenResponse accessTokenResponse = builder.build();
            ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
            this.accessTokenHttpResponseConverter.write(accessTokenResponse, null, httpResponse);

        } else if (((String) additionalParameters.get("grant_type")).equals(AuthorizationGrantType.REFRESH_TOKEN.getValue())) {
            OAuth2AccessTokenResponse.Builder builder = OAuth2AccessTokenResponse.withToken(accessToken.getTokenValue())
                    .tokenType(accessToken.getTokenType())
                    .scopes(accessToken.getScopes());
            if (refreshToken.getExpiresAt() != null) {
                builder.expiresIn(ChronoUnit.SECONDS.between(Instant.now(), refreshToken.getExpiresAt()));
            }
            if (refreshToken != null) {
                builder.refreshToken(refreshToken.getTokenValue());
            }
            OAuth2AccessTokenResponse accessTokenResponse = builder.build();
            ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
            this.accessTokenHttpResponseConverter.write(accessTokenResponse, null, httpResponse);

        } else if (((String) additionalParameters.get("grant_type")).equals(AuthorizationGrantType.AUTHORIZATION_CODE.getValue())) {
            // Authorization Code만 JSON으로 응답
            String code = (String) additionalParameters.get("authorization_code");

            // JSON 응답 생성 (authorization_code만 포함)
            String jsonResponse = String.format("{\"code\":\"%s\"}", code);

            // JSON 응답 전송
            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");
            response.getWriter().write(jsonResponse);

        } else {
            throw new KnifeOauth2AuthenticationException(KnifeErrorMessages.builder()
                    .message("Wrong grant type from Req : " + (String) additionalParameters.get("grant_type"))
                    .userMessage(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_WRONG_GRANT_TYPE))
                    .build());
        }
    }

}
