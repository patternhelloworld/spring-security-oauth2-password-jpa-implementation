package com.patternknife.securityhelper.oauth2.config.security.serivce;

import com.patternknife.securityhelper.oauth2.config.CustomHttpHeaders;
import com.patternknife.securityhelper.oauth2.config.security.dao.CustomOauthAccessTokenRepository;
import com.patternknife.securityhelper.oauth2.config.security.dao.CustomOauthRefreshTokenRepository;
import com.patternknife.securityhelper.oauth2.config.security.dao.OauthAccessTokenRecordRepository;
import com.patternknife.securityhelper.oauth2.config.security.entity.CustomOauthAccessToken;
import com.patternknife.securityhelper.oauth2.config.security.entity.CustomOauthRefreshToken;
import com.patternknife.securityhelper.oauth2.config.security.entity.OauthAccessTokenRecord;
import com.patternknife.securityhelper.oauth2.util.CustomUtils;
import com.patternknife.securityhelper.oauth2.config.security.token.generator.CustomAuthenticationKeyGenerator;
import jakarta.annotation.Nullable;
import jakarta.validation.constraints.NotEmpty;
import lombok.RequiredArgsConstructor;
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

    private final CustomOauthAccessTokenRepository customOauthAccessTokenRepository;
    private final CustomOauthRefreshTokenRepository customOauthRefreshTokenRepository;
    private final OauthAccessTokenRecordRepository oauthAccessTokenRecordRepository;


    /*
    *   1. C for Create
    * */

    /*
        Save Access & Refresh Token in Persistence
    */
    @Override
    public void save(OAuth2Authorization authorization) {

        String appTokenValue = authorization.getAttribute(CustomHttpHeaders.APP_TOKEN);

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

        CustomOauthAccessToken cat = new CustomOauthAccessToken();


        cat.setTokenId(CustomAuthenticationKeyGenerator.hashTokenValueToTokenId(authorization.getAccessToken().getToken().getTokenValue()));
        cat.setToken(authorization.getAccessToken().getToken());
        // Stored as "MD5(username + client_id + app_token)"
        cat.setAuthenticationId(authenticationId);
        cat.setUserName(authorization.getPrincipalName());
        cat.setClientId(authorization.getAttribute("client_id"));
        cat.setAuthentication(authorization);
        cat.setRefreshToken(CustomAuthenticationKeyGenerator.hashTokenValueToTokenId(refreshToken));



        Instant now = Instant.now(); // 현재 시간을 LocalDateTime 객체로 가져옴

        Instant expiresAt = authorization.getAccessToken().getToken().getExpiresAt();
        Integer accessTokenRemainingSeconds = Math.toIntExact(Duration.between(now, expiresAt).getSeconds());

        Duration tokenValidityDuration = Duration.ofSeconds(accessTokenRemainingSeconds); // 토큰의 유효 시간을 Duration으로 변환


        LocalDateTime expirationDateTime = LocalDateTime.now().plus(tokenValidityDuration); // 현재 시간에 토큰의 유효 시간을 더함

        cat.setExpirationDate(expirationDateTime);
        if (appTokenValue != null) {
            cat.setAppToken(appTokenValue);
        }

        String userAgentValue = authorization.getAttribute(CustomHttpHeaders.USER_AGENT);
        if (!CustomUtils.isEmpty(userAgentValue)) {
            cat.setUserAgent(userAgentValue);
        }

        String remoteIp = authorization.getAttribute(CustomHttpHeaders.X_Forwarded_For);
        if (remoteIp != null) {
            cat.setRemoteIp(remoteIp);
        }

        customOauthAccessTokenRepository.save(cat);

        saveRefreshToken(authorization.getRefreshToken().getToken(), authorization);


        try {
            OauthAccessTokenRecord oauthAccessTokenRecord = new OauthAccessTokenRecord();
            oauthAccessTokenRecord.setUserName(cat.getUserName());
            if (cat.getUserAgent() != null) {
                oauthAccessTokenRecord.setUserAgent(cat.getUserAgent());
                oauthAccessTokenRecord.setDeviceType(CustomUtils.getMobileOperatingSystem(cat.getUserAgent()).getValue());
            } else {
                // COMPOSITE PK 이기 때문에 NULL 이 들어가면 안된다.
                oauthAccessTokenRecord.setUserAgent("");
                oauthAccessTokenRecord.setDeviceType(CustomUtils.getMobileOperatingSystem(cat.getUserAgent()).getValue());
            }
            oauthAccessTokenRecordRepository.save(oauthAccessTokenRecord);
        } catch (Exception e) {
            CustomUtils.createNonStoppableErrorMessage("Access Token 과 User-Agent(기기) 로그를 남기는 중 오류 발생", e);
            // Unique Key Exception 이 발생할 수 있으나, 무시. 다만 DataIntegrityViolationException 이 RuntimeException 이라 @Transaction 이 걸려있으면, Roll Back 됨을 확인 필요.
            // [1차 확인됨] UserName 과 UserAgent 를 PK 로 잡아서, JPA 가 SELECT 문을 먼저 실행해서 값이 같으면 INSERT 안함.
            // [2차 확인됨] 이를 호출하는 Security 내부 라이브러리인 DefaultTokenServices 가 @Transactional 범위 내에 있다. (DefaultTokenServices 에 noRollbackFor 가 없으므로 여기에 noRollbackFor 넣어봤자 의미 없다.)
            //             만약 동일한 이 로그인 API 를 동시적으로 약 100번 가량 호출한다면 (그럴일은 없겠지만...) 롤백 가능성이 있다. (75개 동시에 던졌는데 오류가 없다.)
            // [3차 확인됨] 결국 75개 동시에 던져도 오류가 안나서, try 구문에 throw new Exception("ddd"); 이렇게 했더니 롤백 안됨을 확인. 그런데 OauthAccessTokenRecord 엔터티의 테이블 명을 잘못쓰는 오류 수준은 롤백 됨.
            // [4차 확인됨] throw new Exception("ddd"); 를 그냥 Throw 하면 위에 모두 롤백 됨을 확인.
            // [결론] DefaultTokenServices 의 createAccessToken 을 사용하는 함수에 @Transactional 을 붙이지 않게 확인 필요. 이는 그대로 사용.
        }
    }

    /*
        Save Refresh Token in Persistence
    */
    private void saveRefreshToken(OAuth2RefreshToken oAuth2RefreshToken, OAuth2Authorization oAuth2Authorization) {

        CustomOauthRefreshToken crt = new CustomOauthRefreshToken();

        // 새로운 토큰 ID 생성 로직 (필요에 따라 주석 처리된 부분을 참고하여 사용)
        // crt.setId(UUID.randomUUID().toString() + UUID.randomUUID().toString());
        crt.setTokenId(CustomAuthenticationKeyGenerator.hashTokenValueToTokenId(oAuth2RefreshToken.getTokenValue()));
        crt.setToken(oAuth2RefreshToken);
        crt.setAuthentication(oAuth2Authorization);

        // OAuth2RefreshToken.getExpiresAt()는 이제 Instant 를 반환합니다.
        LocalDateTime localDateTimeExpiration = LocalDateTime.ofInstant(
                Objects.requireNonNull(oAuth2RefreshToken.getExpiresAt()),
                ZoneId.systemDefault()
        );
        crt.setExpirationDate(localDateTimeExpiration);

        customOauthRefreshTokenRepository.save(crt);
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

            return findOAuth2AuthorizationByCustomOauthRefreshTokenSafely(() -> customOauthRefreshTokenRepository.findByTokenId(tokenId), e -> {
                List<CustomOauthRefreshToken> customOauthRefreshTokens = customOauthRefreshTokenRepository.findAllByTokenId(tokenId).orElse(null);
                if (customOauthRefreshTokens != null) {
                    for (CustomOauthRefreshToken customOauthRefreshToken : customOauthRefreshTokens) {
                        customOauthRefreshTokenRepository.deleteByTokenId(customOauthRefreshToken.getTokenId());
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
            Supplier<Optional<CustomOauthAccessToken>> accessTokenSupplier, Consumer<Exception> exceptionHandler) {
        CustomOauthAccessToken customOauthAccessToken = null;
        OAuth2Authorization oAuth2Authorization = null;
        try {
            customOauthAccessToken = accessTokenSupplier.get().orElse(null);
            if (customOauthAccessToken != null) {
                oAuth2Authorization = customOauthAccessToken.getAuthentication();
            }
        } catch (Exception e) {
            exceptionHandler.accept(e);
        }
        if (customOauthAccessToken != null && oAuth2Authorization != null && oAuth2Authorization.getAccessToken() != null && oAuth2Authorization.getAccessToken().isExpired()) {
            customOauthAccessTokenRepository.deleteByTokenId(customOauthAccessToken.getTokenId());
        }

        return oAuth2Authorization;
    }
    @Override
    public @Nullable OAuth2Authorization findById(@NotEmpty String tokenId) {
        return findOAuth2AuthorizationByCustomOauthAccessTokenSafely(() -> customOauthAccessTokenRepository.findByTokenId(tokenId), e -> {
            List<CustomOauthAccessToken> customOauthAccessTokens = customOauthAccessTokenRepository.findAllByTokenId(tokenId).orElse(null);
            if (customOauthAccessTokens != null) {
                for (CustomOauthAccessToken customOauthAccessToken : customOauthAccessTokens) {
                    customOauthAccessTokenRepository.deleteByTokenId(tokenId);
                    customOauthRefreshTokenRepository.deleteByTokenId(customOauthAccessToken.getRefreshToken());
                }
            }
        });

    }
    /*
     *   중요. KEY 는 Username, ClientId, AppToken 이 가 된다. 이 함수를 다른 기준으로 구현.
     * */
    public @Nullable OAuth2Authorization findByUserNameAndClientIdAndAppToken(@NotEmpty String username, @NotEmpty String clientId, @Nullable String appTokenValue) {
        return findOAuth2AuthorizationByCustomOauthAccessTokenSafely(() -> customOauthAccessTokenRepository.findByUserNameAndClientIdAndAppToken(username, clientId, appTokenValue),
                e -> {
                    List<CustomOauthAccessToken> customOauthAccessTokens = customOauthAccessTokenRepository.findListByUserNameAndClientIdAndAppToken(username, clientId, appTokenValue).orElse(null);
                    if (customOauthAccessTokens != null) {
                        for (CustomOauthAccessToken customOauthAccessToken : customOauthAccessTokens) {
                            customOauthAccessTokenRepository.deleteByUserNameAndClientIdAndAppToken(username, clientId, appTokenValue);
                            customOauthRefreshTokenRepository.deleteByTokenId(customOauthAccessToken.getRefreshToken());
                        }
                    }
                });
    }
    /*
     *    3) RefreshToken Token R
     * */
    private @Nullable OAuth2Authorization findOAuth2AuthorizationByCustomOauthRefreshTokenSafely(Supplier<Optional<CustomOauthRefreshToken>> refreshTokenSupplier, Consumer<Exception> exceptionHandler) {
        CustomOauthRefreshToken customOauthRefreshToken = null;
        OAuth2Authorization oAuth2Authorization = null;
        try {
            customOauthRefreshToken = refreshTokenSupplier.get().orElse(null);
            if (customOauthRefreshToken != null) {
                oAuth2Authorization = customOauthRefreshToken.getAuthentication();
            }
        } catch (Exception e) {
            exceptionHandler.accept(e);
        }

        if (customOauthRefreshToken != null && oAuth2Authorization != null && oAuth2Authorization.getRefreshToken() != null && oAuth2Authorization.getRefreshToken().isExpired()) {
            customOauthRefreshTokenRepository.deleteByTokenId(customOauthRefreshToken.getTokenId());
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
            }
        } else {
            // Ignore NOT throwing any errors.
        }
    }

    /*
        Remove Access Token From Persistence
     */
    private void removeAccessToken(OAuth2AccessToken oAuth2AccessToken) {
        Optional<CustomOauthAccessToken> accessToken = customOauthAccessTokenRepository.findByTokenId(CustomAuthenticationKeyGenerator.hashTokenValueToTokenId(oAuth2AccessToken.getTokenValue()));
        accessToken.ifPresent(customOauthAccessTokenRepository::delete);
    }

    private void removeRefreshToken(OAuth2RefreshToken oAuth2RefreshToken) {
        Optional<CustomOauthRefreshToken> refreshToken = customOauthRefreshTokenRepository.findByTokenId(CustomAuthenticationKeyGenerator.hashTokenValueToTokenId(oAuth2RefreshToken.getTokenValue()));
        refreshToken.ifPresent(customOauthRefreshTokenRepository::delete);
    }




}
