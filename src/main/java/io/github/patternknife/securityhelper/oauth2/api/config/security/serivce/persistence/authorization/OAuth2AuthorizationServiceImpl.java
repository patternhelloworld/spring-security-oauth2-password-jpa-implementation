package io.github.patternknife.securityhelper.oauth2.api.config.security.serivce.persistence.authorization;


import io.github.patternknife.securityhelper.oauth2.api.config.security.aop.SecurityPointCut;
import io.github.patternknife.securityhelper.oauth2.api.config.security.dao.KnifeAuthorizationRepository;
import io.github.patternknife.securityhelper.oauth2.api.config.security.entity.KnifeAuthorization;
import io.github.patternknife.securityhelper.oauth2.api.config.security.token.generator.CustomAuthenticationKeyGenerator;
import io.github.patternknife.securityhelper.oauth2.api.config.security.util.KnifeHttpHeaders;

import jakarta.annotation.Nullable;
import jakarta.validation.constraints.NotEmpty;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.List;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.function.Supplier;

@Configuration
@RequiredArgsConstructor
public class OAuth2AuthorizationServiceImpl implements OAuth2AuthorizationService {

    private final KnifeAuthorizationRepository knifeAuthorizationRepository;
    private final SecurityPointCut securityPointCut;

    /*
    *   1. C for Create
    * */

    /*
         1) Remove previous Access & Refresh Tokens for current OAuth2Authorization from Persistence
         2) Save Access & Refresh Tokens for current OAuth2Authorization into Persistence
         3) Only Insert (shouldBeNewAuthorization)
    */
    @Override
    public void save(OAuth2Authorization shouldBeNewAuthorization) {


        KnifeAuthorization knifeAuthorization = new KnifeAuthorization();


        knifeAuthorization.setId(shouldBeNewAuthorization.getId());

        knifeAuthorization.setPrincipalName(shouldBeNewAuthorization.getPrincipalName());
        knifeAuthorization.setRegisteredClientId(shouldBeNewAuthorization.getAttribute("client_id"));
        knifeAuthorization.setAccessTokenValue(shouldBeNewAuthorization.getAccessToken().getToken().getTokenValue());
        knifeAuthorization.setRefreshTokenValue(shouldBeNewAuthorization.getRefreshToken().getToken().getTokenValue());

        String appTokenValue = shouldBeNewAuthorization.getAttribute(KnifeHttpHeaders.APP_TOKEN);
        if (appTokenValue != null) {
            knifeAuthorization.setAccessTokenAppToken(appTokenValue);
        }

        String userAgentValue = shouldBeNewAuthorization.getAttribute(KnifeHttpHeaders.USER_AGENT);
        if (!StringUtils.isEmpty(userAgentValue)) {
            knifeAuthorization.setAccessTokenUserAgent(userAgentValue);
        }

        String remoteIp = shouldBeNewAuthorization.getAttribute(KnifeHttpHeaders.X_Forwarded_For);
        if (remoteIp != null) {
            knifeAuthorization.setAccessTokenRemoteIp(remoteIp);
        }

        knifeAuthorization.setAttributes(shouldBeNewAuthorization);
        knifeAuthorization.setAccessTokenType(shouldBeNewAuthorization.getAuthorizationGrantType().getValue());
        knifeAuthorization.setAccessTokenScopes(String.join(",", shouldBeNewAuthorization.getAuthorizedScopes()));

        // Token Expiration
        knifeAuthorization.setAccessTokenIssuedAt(LocalDateTime.ofInstant(Instant.now(), ZoneId.systemDefault()));
        if (shouldBeNewAuthorization.getAccessToken().getToken().getExpiresAt() != null) {
            knifeAuthorization.setAccessTokenExpiresAt(LocalDateTime.ofInstant(shouldBeNewAuthorization.getAccessToken().getToken().getExpiresAt(), ZoneId.systemDefault()));
        }

        // Token Expiration
        knifeAuthorization.setRefreshTokenIssuedAt(LocalDateTime.ofInstant(Instant.now(), ZoneId.systemDefault()));
        if (shouldBeNewAuthorization.getRefreshToken().getToken().getExpiresAt() != null) {
            knifeAuthorization.setRefreshTokenExpiresAt(LocalDateTime.ofInstant(shouldBeNewAuthorization.getRefreshToken().getToken().getExpiresAt(), ZoneId.systemDefault()));
        }


        knifeAuthorizationRepository.save(knifeAuthorization);

        if(securityPointCut != null){
            securityPointCut.afterTokensSaved(knifeAuthorization, null);
        }

    }

    /*
    *   2. R for Read
    * */

    /*
    *    1) AccessToken Token R + RefreshToken Token R
    * */
    @Override
    public OAuth2Authorization findByToken(@NotEmpty String tokenValue, @Nullable OAuth2TokenType tokenType) {

        String hashedTokenValue = CustomAuthenticationKeyGenerator.hashTokenValue(tokenValue);

        if (tokenType != null && tokenType.equals(OAuth2TokenType.ACCESS_TOKEN)) {
            return knifeAuthorizationRepository.findByAccessTokenValue(hashedTokenValue).map(KnifeAuthorization::getAttributes).orElse(null);
        } else if (tokenType != null && tokenType.equals(OAuth2TokenType.REFRESH_TOKEN)) {
            return knifeAuthorizationRepository.findByRefreshTokenValue(hashedTokenValue).map(KnifeAuthorization::getAttributes).orElse(null);
        } else {
            return knifeAuthorizationRepository.findByStateOrAuthorizationCodeValueOrAccessTokenValueOrRefreshTokenValueOrOidcIdTokenValueOrUserCodeValueOrDeviceCodeValue(hashedTokenValue).map(KnifeAuthorization::getAttributes).orElse(null);
        }
    }
    /*
    *    2) AccessToken Token R
    * */
    private @Nullable OAuth2Authorization findOAuth2AuthorizationByAccessTokenValueSafely(Supplier<Optional<OAuth2Authorization>> authorizationSupplier, Consumer<Exception> exceptionHandler) {

        OAuth2Authorization oAuth2Authorization = null;
        try {
            oAuth2Authorization = authorizationSupplier.get().orElse(null);

        } catch (Exception e) {

            exceptionHandler.accept(e);

            // Retry only one more time
            oAuth2Authorization = authorizationSupplier.get().orElse(null);

        }

        if (oAuth2Authorization != null && oAuth2Authorization.getAccessToken() != null
                && oAuth2Authorization.getAccessToken().isExpired()) {
            // 만료됨
            knifeAuthorizationRepository.deleteByAccessTokenValue(oAuth2Authorization.getAccessToken().getToken().getTokenValue());

            return null;
        }
        return oAuth2Authorization;
    }


    
    @Override
    public @Nullable OAuth2Authorization findById(String id) {
        return knifeAuthorizationRepository.findById(id)
                .map(KnifeAuthorization::getAttributes)
                .orElse(null);

    }
    /*
     *   [IMPORTANT] KEY = Username (principalName) + ClientId + AppToken
     *      Same ( org.springframework.security.core.userdetails : userName + spring-authorization-server : principalName )
     * */
    public @Nullable OAuth2Authorization findByUserNameAndClientIdAndAppToken(@NotEmpty String userName, @NotEmpty String clientId, @Nullable String appToken) {
        return findOAuth2AuthorizationByAccessTokenValueSafely(() -> knifeAuthorizationRepository.findValidAuthorizationByPrincipalNameAndClientIdAndAppToken(userName, clientId, appToken).map(KnifeAuthorization::getAttributes),
                e -> {
                    knifeAuthorizationRepository.findListByPrincipalNameAndRegisteredClientIdAndAccessTokenAppToken(userName, clientId, appToken).ifPresent(knifeAuthorizationRepository::deleteAll);
                    knifeAuthorizationRepository.deleteByPrincipalNameAndRegisteredClientIdAndAccessTokenAppToken(userName, clientId, appToken);
                });
    }



    /*
    *   4. D for Delete
    * */
    /*
       Remove Access & Refresh Token From Persistence
    */
    @Override
    public void remove(OAuth2Authorization authorization) {
        if (authorization != null) {
            knifeAuthorizationRepository.deleteById(authorization.getId());
            // authorization.getId()
            removeAccessToken(authorization.getAccessToken().getToken());
            if (authorization.getRefreshToken() != null) {
                removeRefreshToken(authorization.getRefreshToken().getToken());
            }else {
                // Ignore NOT throwing any errors.
            }
        } else {
            // Ignore NOT throwing any errors.
        }
    }

    /*
        Remove Access Token From Persistence
     */
    private void removeAccessToken(OAuth2AccessToken oAuth2AccessToken) {
        Optional<KnifeAuthorization> knifeAuthorization = knifeAuthorizationRepository.findByAccessTokenValue(CustomAuthenticationKeyGenerator.hashTokenValue(oAuth2AccessToken.getTokenValue()));
        knifeAuthorization.ifPresent(knifeAuthorizationRepository::delete);
    }

    private void removeRefreshToken(OAuth2RefreshToken oAuth2RefreshToken) {
        Optional<KnifeAuthorization> knifeAuthorization = knifeAuthorizationRepository.findByRefreshTokenValue(CustomAuthenticationKeyGenerator.hashTokenValue(oAuth2RefreshToken.getTokenValue()));
        knifeAuthorization.ifPresent(knifeAuthorizationRepository::delete);
    }




}
