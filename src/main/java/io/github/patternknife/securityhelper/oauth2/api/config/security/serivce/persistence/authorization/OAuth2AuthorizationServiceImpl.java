package io.github.patternknife.securityhelper.oauth2.api.config.security.serivce.persistence.authorization;


import io.github.patternknife.securityhelper.oauth2.api.config.security.entity.KnifeOauthRefreshToken;
import io.github.patternknife.securityhelper.oauth2.api.config.security.util.KnifeHttpHeaders;
import io.github.patternknife.securityhelper.oauth2.api.config.security.aop.SecurityPointCut;
import io.github.patternknife.securityhelper.oauth2.api.config.security.dao.KnifeOauthAccessTokenRepository;
import io.github.patternknife.securityhelper.oauth2.api.config.security.dao.KnifeOauthRefreshTokenRepository;
import io.github.patternknife.securityhelper.oauth2.api.config.security.entity.KnifeOauthAccessToken;
import io.github.patternknife.securityhelper.oauth2.api.config.security.token.generator.CustomAuthenticationKeyGenerator;

import jakarta.annotation.Nullable;
import jakarta.validation.constraints.NotEmpty;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.context.annotation.Configuration;
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
import java.util.Objects;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.function.Supplier;

@Configuration
@RequiredArgsConstructor
public class OAuth2AuthorizationServiceImpl implements OAuth2AuthorizationService {

    private final KnifeOauthAccessTokenRepository knifeOauthAccessTokenRepository;
    private final KnifeOauthRefreshTokenRepository knifeOauthRefreshTokenRepository;
    private final SecurityPointCut securityPointCut;

    /*
    *   1. C for Create
    * */

    /*
        Save Access & Refresh Token in Persistence
    */
    @Override
    public void save(OAuth2Authorization authorization) {

        String appTokenValue = authorization.getAttribute(KnifeHttpHeaders.APP_TOKEN);

        String refreshToken = null;
        if (authorization.getRefreshToken() != null) {
            refreshToken = authorization.getRefreshToken().getToken().getTokenValue();
        }
        if (authorization.getAccessToken() != null) {
            if (findByToken(authorization.getAccessToken().getToken().getTokenValue(), OAuth2TokenType.ACCESS_TOKEN) != null) {
                this.remove(authorization);
            }
        }


        String authenticationId = CustomAuthenticationKeyGenerator.hashUniqueCompositeColumnsToAuthenticationId(authorization, appTokenValue);

        KnifeOauthAccessToken cat = new KnifeOauthAccessToken();


        cat.setTokenId(CustomAuthenticationKeyGenerator.hashTokenValueToTokenId(authorization.getAccessToken().getToken().getTokenValue()));
        cat.setToken(authorization.getAccessToken().getToken());
        // Stored as "MD5(username + client_id + app_token)"
        cat.setAuthenticationId(authenticationId);
        cat.setUserName(authorization.getPrincipalName());
        cat.setClientId(authorization.getAttribute("client_id"));
        cat.setAuthentication(authorization);
        cat.setRefreshToken(CustomAuthenticationKeyGenerator.hashTokenValueToTokenId(refreshToken));


        Instant now = Instant.now();

        Instant expiresAt = authorization.getAccessToken().getToken().getExpiresAt();
        Integer accessTokenRemainingSeconds = Math.toIntExact(Duration.between(now, expiresAt).getSeconds());

        Duration tokenValidityDuration = Duration.ofSeconds(accessTokenRemainingSeconds);


        LocalDateTime expirationDateTime = LocalDateTime.now().plus(tokenValidityDuration);

        cat.setExpirationDate(expirationDateTime);
        if (appTokenValue != null) {
            cat.setAppToken(appTokenValue);
        }

        String userAgentValue = authorization.getAttribute(KnifeHttpHeaders.USER_AGENT);
        if (!StringUtils.isEmpty(userAgentValue)) {
            cat.setUserAgent(userAgentValue);
        }

        String remoteIp = authorization.getAttribute(KnifeHttpHeaders.X_Forwarded_For);
        if (remoteIp != null) {
            cat.setRemoteIp(remoteIp);
        }

        knifeOauthAccessTokenRepository.save(cat);

        saveRefreshToken(authorization.getRefreshToken().getToken(), authorization);

        if(securityPointCut != null){
            securityPointCut.afterTokensSaved(cat, null, null);
        }

    }

    /*
        Save Refresh Token in Persistence
    */
    private void saveRefreshToken(OAuth2RefreshToken oAuth2RefreshToken, OAuth2Authorization oAuth2Authorization) {

        KnifeOauthRefreshToken crt = new KnifeOauthRefreshToken();


        // crt.setId(UUID.randomUUID().toString() + UUID.randomUUID().toString());
        crt.setTokenId(CustomAuthenticationKeyGenerator.hashTokenValueToTokenId(oAuth2RefreshToken.getTokenValue()));
        crt.setToken(oAuth2RefreshToken);
        crt.setAuthentication(oAuth2Authorization);


        LocalDateTime localDateTimeExpiration = LocalDateTime.ofInstant(
                Objects.requireNonNull(oAuth2RefreshToken.getExpiresAt()),
                ZoneId.systemDefault()
        );
        crt.setExpirationDate(localDateTimeExpiration);

        knifeOauthRefreshTokenRepository.save(crt);
    }


    /*
    *   2. R for Read
    * */

    /*
    *    1) AccessToken Token R + RefreshToken Token R
    * */
    @Override
    public OAuth2Authorization findByToken(@NotEmpty String tokenValue, @NotEmpty OAuth2TokenType tokenType) {

        assert tokenType != null;

        String tokenId = CustomAuthenticationKeyGenerator.hashTokenValueToTokenId(tokenValue);

        if (tokenType.equals(OAuth2TokenType.ACCESS_TOKEN)) {

            return findById(tokenId);

        } else if (tokenType.equals(OAuth2TokenType.REFRESH_TOKEN)) {

            return findOAuth2AuthorizationByCustomOauthRefreshTokenSafely(() -> knifeOauthRefreshTokenRepository.findByTokenId(tokenId), e -> {
                List<KnifeOauthRefreshToken> knifeOauthRefreshTokens = knifeOauthRefreshTokenRepository.findAllByTokenId(tokenId).orElse(null);
                if (knifeOauthRefreshTokens != null) {
                    for (KnifeOauthRefreshToken knifeOauthRefreshToken : knifeOauthRefreshTokens) {
                        knifeOauthRefreshTokenRepository.deleteByTokenId(knifeOauthRefreshToken.getTokenId());
                    }
                }
            });

        } else {
            throw new IllegalStateException("Wrong Oauth Token Type : " + tokenType.getValue());
        }
    }
    /*
    *    2) AccessToken Token R
    * */
    private @Nullable OAuth2Authorization findOAuth2AuthorizationByCustomOauthAccessTokenSafely(
            Supplier<Optional<KnifeOauthAccessToken>> accessTokenSupplier, Consumer<Exception> exceptionHandler) {
        KnifeOauthAccessToken knifeOauthAccessToken = null;
        OAuth2Authorization oAuth2Authorization = null;
        try {
            knifeOauthAccessToken = accessTokenSupplier.get().orElse(null);
            if (knifeOauthAccessToken != null) {
                oAuth2Authorization = knifeOauthAccessToken.getAuthentication();
            }
        } catch (Exception e) {

            exceptionHandler.accept(e);

            // Retry only one more time
            knifeOauthAccessToken = accessTokenSupplier.get().orElse(null);
            if (knifeOauthAccessToken != null) {
                oAuth2Authorization = knifeOauthAccessToken.getAuthentication();
            }
        }
        if (knifeOauthAccessToken != null && oAuth2Authorization != null && oAuth2Authorization.getAccessToken() != null && oAuth2Authorization.getAccessToken().isExpired()) {
            knifeOauthAccessTokenRepository.deleteByTokenId(knifeOauthAccessToken.getTokenId());
            return null;
        }

        return oAuth2Authorization;
    }
    @Override
    public @Nullable OAuth2Authorization findById(@NotEmpty String tokenId) {
        return findOAuth2AuthorizationByCustomOauthAccessTokenSafely(() -> knifeOauthAccessTokenRepository.findByTokenId(tokenId), e -> {
            List<KnifeOauthAccessToken> knifeOauthAccessTokens = knifeOauthAccessTokenRepository.findAllByTokenId(tokenId).orElse(null);
            if (knifeOauthAccessTokens != null) {
                for (KnifeOauthAccessToken knifeOauthAccessToken : knifeOauthAccessTokens) {
                    knifeOauthAccessTokenRepository.deleteByTokenId(tokenId);
                    knifeOauthRefreshTokenRepository.deleteByTokenId(knifeOauthAccessToken.getRefreshToken());
                }
            }
        });

    }
    /*
     *   [IMPORTANT] KEY = Username + ClientId + AppToken
     * */
    public @Nullable OAuth2Authorization findByUserNameAndClientIdAndAppToken(@NotEmpty String username, @NotEmpty String clientId, @Nullable String appTokenValue) {
        return findOAuth2AuthorizationByCustomOauthAccessTokenSafely(() -> knifeOauthAccessTokenRepository.findByUserNameAndClientIdAndAppToken(username, clientId, appTokenValue),
                e -> {
                    List<KnifeOauthAccessToken> knifeOauthAccessTokens = knifeOauthAccessTokenRepository.findListByUserNameAndClientIdAndAppToken(username, clientId, appTokenValue).orElse(null);
                    if (knifeOauthAccessTokens != null) {
                        for (KnifeOauthAccessToken knifeOauthAccessToken : knifeOauthAccessTokens) {
                            knifeOauthAccessTokenRepository.deleteByUserNameAndClientIdAndAppToken(username, clientId, appTokenValue);
                            knifeOauthRefreshTokenRepository.deleteByTokenId(knifeOauthAccessToken.getRefreshToken());
                        }
                    }
                });
    }
    /*
     *    3) RefreshToken Token R
     * */
    private @Nullable OAuth2Authorization findOAuth2AuthorizationByCustomOauthRefreshTokenSafely(Supplier<Optional<KnifeOauthRefreshToken>> refreshTokenSupplier, Consumer<Exception> exceptionHandler) {
        KnifeOauthRefreshToken knifeOauthRefreshToken = null;
        OAuth2Authorization oAuth2Authorization = null;
        try {
            knifeOauthRefreshToken = refreshTokenSupplier.get().orElse(null);
            if (knifeOauthRefreshToken != null) {
                oAuth2Authorization = knifeOauthRefreshToken.getAuthentication();
            }
        } catch (Exception e) {

            exceptionHandler.accept(e);

            // Retry only one more time
            knifeOauthRefreshToken = refreshTokenSupplier.get().orElse(null);
            if (knifeOauthRefreshToken != null) {
                oAuth2Authorization = knifeOauthRefreshToken.getAuthentication();
            }
        }

        if (knifeOauthRefreshToken != null && oAuth2Authorization != null && oAuth2Authorization.getRefreshToken() != null && oAuth2Authorization.getRefreshToken().isExpired()) {
            knifeOauthRefreshTokenRepository.deleteByTokenId(knifeOauthRefreshToken.getTokenId());
            return null;
        }
        return oAuth2Authorization;
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
        Optional<KnifeOauthAccessToken> accessToken = knifeOauthAccessTokenRepository.findByTokenId(CustomAuthenticationKeyGenerator.hashTokenValueToTokenId(oAuth2AccessToken.getTokenValue()));
        accessToken.ifPresent(knifeOauthAccessTokenRepository::delete);
    }

    private void removeRefreshToken(OAuth2RefreshToken oAuth2RefreshToken) {
        Optional<KnifeOauthRefreshToken> refreshToken = knifeOauthRefreshTokenRepository.findByTokenId(CustomAuthenticationKeyGenerator.hashTokenValueToTokenId(oAuth2RefreshToken.getTokenValue()));
        refreshToken.ifPresent(knifeOauthRefreshTokenRepository::delete);
    }




}
