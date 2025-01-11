package io.github.patternhelloworld.securityhelper.oauth2.api.config.security.serivce.persistence.authorization;


import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.aop.SecurityPointCut;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.dao.EasyPlusAuthorizationRepository;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.entity.EasyPlusAuthorization;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.token.generator.CustomAuthenticationKeyGenerator;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.util.EasyPlusHttpHeaders;
import jakarta.annotation.Nullable;
import jakarta.validation.constraints.NotEmpty;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.function.Supplier;

/**
 *   According to the 'OAuth2AuthorizationService' implementation,
 *     When a single value is expected to be returned, there's no need to explicitly end the function name with "One".
 *     So when multiple values are expected to be returned, I have made the function name end with "List" to distinguish them.
 * @author Andrew Kang
 * @since 0.0.O
 * @see OAuth2Authorization
 * @see EasyPlusAuthorization
 */
@Configuration
@RequiredArgsConstructor
public class OAuth2AuthorizationServiceImpl implements OAuth2AuthorizationService {

    private static final Logger logger = LoggerFactory.getLogger(OAuth2AuthorizationServiceImpl.class);

    private final EasyPlusAuthorizationRepository easyPlusAuthorizationRepository;
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


        EasyPlusAuthorization easyPlusAuthorization = new EasyPlusAuthorization();

        easyPlusAuthorization.setId(shouldBeNewAuthorization.getId());
        easyPlusAuthorization.setPrincipalName(shouldBeNewAuthorization.getPrincipalName());

        if (shouldBeNewAuthorization.getAttribute("response_type") != null &&
                OAuth2ParameterNames.CODE.equals(shouldBeNewAuthorization.getAttribute("response_type"))) {
            // Authorization Code
            easyPlusAuthorization.setRegisteredClientId(shouldBeNewAuthorization.getAttribute("client_id"));
            OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCodeToken = shouldBeNewAuthorization.getToken(OAuth2AuthorizationCode.class);
            if (authorizationCodeToken != null) {
                easyPlusAuthorization.setAuthorizationCodeValue(CustomAuthenticationKeyGenerator.hashTokenValue(authorizationCodeToken.getToken().getTokenValue()));
                easyPlusAuthorization.setAuthorizationCodeIssuedAt(LocalDateTime.ofInstant(authorizationCodeToken.getToken().getIssuedAt(), ZoneId.systemDefault()));
                if (authorizationCodeToken.getToken().getExpiresAt() != null) {
                    easyPlusAuthorization.setAuthorizationCodeExpiresAt(LocalDateTime.ofInstant(authorizationCodeToken.getToken().getExpiresAt(), ZoneId.systemDefault()));
                }
            }
        }else{

            easyPlusAuthorization.setRegisteredClientId(shouldBeNewAuthorization.getAttribute("client_id"));

            if(shouldBeNewAuthorization.getAccessToken() != null) {
                easyPlusAuthorization.hashSetAccessTokenValue(shouldBeNewAuthorization.getAccessToken().getToken().getTokenValue());
            }
            if(shouldBeNewAuthorization.getRefreshToken() != null) {
                easyPlusAuthorization.hashSetRefreshTokenValue(shouldBeNewAuthorization.getRefreshToken().getToken().getTokenValue());
            }

            String appTokenValue = shouldBeNewAuthorization.getAttribute(EasyPlusHttpHeaders.APP_TOKEN);
            if (appTokenValue != null) {
                easyPlusAuthorization.setAccessTokenAppToken(appTokenValue);
            }

            String userAgentValue = shouldBeNewAuthorization.getAttribute(EasyPlusHttpHeaders.USER_AGENT);
            if (!StringUtils.isEmpty(userAgentValue)) {
                easyPlusAuthorization.setAccessTokenUserAgent(userAgentValue);
            }

            String remoteIp = shouldBeNewAuthorization.getAttribute(EasyPlusHttpHeaders.X_Forwarded_For);
            if (remoteIp != null) {
                easyPlusAuthorization.setAccessTokenRemoteIp(remoteIp);
            }

            easyPlusAuthorization.setAccessTokenType(shouldBeNewAuthorization.getAuthorizationGrantType().getValue());
            easyPlusAuthorization.setAccessTokenScopes(String.join(",", shouldBeNewAuthorization.getAuthorizedScopes()));

            // Token Expiration
            easyPlusAuthorization.setAccessTokenIssuedAt(LocalDateTime.ofInstant(Instant.now(), ZoneId.systemDefault()));
            if (shouldBeNewAuthorization.getAccessToken() != null && shouldBeNewAuthorization.getAccessToken().getToken().getExpiresAt() != null) {
                easyPlusAuthorization.setAccessTokenExpiresAt(LocalDateTime.ofInstant(shouldBeNewAuthorization.getAccessToken().getToken().getExpiresAt(), ZoneId.systemDefault()));
            }

            // Token Expiration
            easyPlusAuthorization.setRefreshTokenIssuedAt(LocalDateTime.ofInstant(Instant.now(), ZoneId.systemDefault()));
            if (shouldBeNewAuthorization.getRefreshToken() != null && shouldBeNewAuthorization.getRefreshToken().getToken().getExpiresAt() != null) {
                easyPlusAuthorization.setRefreshTokenExpiresAt(LocalDateTime.ofInstant(shouldBeNewAuthorization.getRefreshToken().getToken().getExpiresAt(), ZoneId.systemDefault()));
            }
            easyPlusAuthorization.setAuthorizationGrantType(shouldBeNewAuthorization.getAttribute("grant_type"));
        }

        easyPlusAuthorization.setAttributes(shouldBeNewAuthorization);

        easyPlusAuthorizationRepository.save(easyPlusAuthorization);

        if(securityPointCut != null){
            securityPointCut.afterTokensSaved(easyPlusAuthorization, null);
        }

    }

    /*
    *   2. R for Read
    *     : EasyPlusAuthorization::getAttributes
    * */

    @Override
    public OAuth2Authorization findByToken(@NotEmpty String tokenValue, @Nullable OAuth2TokenType tokenType) {

        String hashedTokenValue = CustomAuthenticationKeyGenerator.hashTokenValue(tokenValue);

        if (tokenType != null && tokenType.equals(OAuth2TokenType.ACCESS_TOKEN)) {
            return easyPlusAuthorizationRepository.findByAccessTokenValue(hashedTokenValue).map(EasyPlusAuthorization::getAttributes).orElse(null);
        } else if (tokenType != null && tokenType.equals(OAuth2TokenType.REFRESH_TOKEN)) {
            return easyPlusAuthorizationRepository.findByRefreshTokenValue(hashedTokenValue).map(EasyPlusAuthorization::getAttributes).orElse(null);
        }else if (tokenType != null && tokenType.equals(new OAuth2TokenType(OAuth2ParameterNames.CODE))) {
            return easyPlusAuthorizationRepository.findByAuthorizationCodeValue(hashedTokenValue).map(EasyPlusAuthorization::getAttributes).orElse(null);
        }  else {
            return easyPlusAuthorizationRepository.findByStateOrAuthorizationCodeValueOrAccessTokenValueOrRefreshTokenValueOrOidcIdTokenValueOrUserCodeValueOrDeviceCodeValue(hashedTokenValue).map(EasyPlusAuthorization::getAttributes).orElse(null);
        }
    }

    @Override
    public @Nullable OAuth2Authorization findById(String id) {
        return easyPlusAuthorizationRepository.findById(id)
                .map(EasyPlusAuthorization::getAttributes)
                .orElse(null);
    }


    public @Nullable OAuth2Authorization findByAuthorizationCode(String authorizationCode) {
        return easyPlusAuthorizationRepository.findByAuthorizationCodeValue(CustomAuthenticationKeyGenerator.hashTokenValue(authorizationCode))
                .map(EasyPlusAuthorization::getAttributes)
                .orElse(null);
    }


    @Value("${io.github.patternhelloworld.securityhelper.oauth2.no-app-token-same-access-token:true}")
    private boolean noAppTokenSameAccessToken;
    /*
     *   [IMPORTANT] KEY = Username (principalName) + ClientId + AppToken
     *      Same ( org.springframework.security.core.userdetails : userName + spring-authorization-server : principalName )
     * */
    /**
     * Returns the {@link OAuth2Authorization} identified by the provided {@code Username (principalName) + ClientId + AppToken}, or
     * {@code null} if not found.
     * @param userName org.springframework.security.core.userdetails, which is same as principalName
     * @param clientId Oauth2 ROPC client_id
     * @param appToken See the README
     * @return the {@link OAuth2Authorization} if found, otherwise {@code null}
     */
    public @Nullable OAuth2Authorization findByUserNameAndClientIdAndAppToken(@NotEmpty String userName, @NotEmpty String clientId, @Nullable String appToken) {
        if (noAppTokenSameAccessToken) {
            return findSafelyByPrincipalNameAndClientIdAndAppToken(() -> easyPlusAuthorizationRepository.findValidAuthorizationByPrincipalNameAndClientIdAndNullableAppToken(userName, clientId, appToken), userName, clientId, appToken);
        } else {
            return findSafelyByPrincipalNameAndClientIdAndAppToken(() -> easyPlusAuthorizationRepository.findValidAuthorizationByPrincipalNameAndClientIdAndAppToken(userName, clientId, appToken), userName, clientId, appToken);
        }
    }

    private @Nullable OAuth2Authorization findSafelyByPrincipalNameAndClientIdAndAppToken(Supplier<Optional<EasyPlusAuthorization>> authorizationSupplier, String userName, String clientId, @Nullable String appToken) {
        return findByAccessTokenValueSafely(() -> authorizationSupplier.get().map(EasyPlusAuthorization::getAttributes),
                e -> {

                    logger.warn("Error finding authorization for user: {}, clientId: {}, appToken: {}", userName, clientId, appToken, e);

                    // If multiple results are detected or other unexpected errors occur, remove access tokens for the account to prevent login errors.
                    easyPlusAuthorizationRepository.findListByPrincipalNameAndRegisteredClientIdAndAccessTokenAppToken(userName, clientId, appToken).ifPresent(easyPlusAuthorizationRepository::deleteAll);
                    easyPlusAuthorizationRepository.deleteByPrincipalNameAndRegisteredClientIdAndAccessTokenAppToken(userName, clientId, appToken);
                });
    }

    private @Nullable OAuth2Authorization findByAccessTokenValueSafely(Supplier<Optional<OAuth2Authorization>> authorizationSupplier, Consumer<Exception> exceptionHandler) {

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
            easyPlusAuthorizationRepository.deleteByAccessTokenValue(oAuth2Authorization.getAccessToken().getToken().getTokenValue());

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
            easyPlusAuthorizationRepository.deleteById(authorization.getId());
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
        Remove Access & Refresh Token From Persistence
     */
    private void removeAccessToken(OAuth2AccessToken oAuth2AccessToken) {
        Optional<EasyPlusAuthorization> easyPlusAuthorization = easyPlusAuthorizationRepository.findByAccessTokenValue(CustomAuthenticationKeyGenerator.hashTokenValue(oAuth2AccessToken.getTokenValue()));
        easyPlusAuthorization.ifPresent(easyPlusAuthorizationRepository::delete);
    }
    private void removeRefreshToken(OAuth2RefreshToken oAuth2RefreshToken) {
        Optional<EasyPlusAuthorization> easyPlusAuthorization = easyPlusAuthorizationRepository.findByRefreshTokenValue(CustomAuthenticationKeyGenerator.hashTokenValue(oAuth2RefreshToken.getTokenValue()));
        easyPlusAuthorization.ifPresent(easyPlusAuthorizationRepository::delete);
    }


    /*
        Once an access token is generated from an authorization code, the code should be removed for security reasons.
    * */
    public void remove(String authorizationCode) {
        easyPlusAuthorizationRepository.deleteByAuthorizationCodeValue(CustomAuthenticationKeyGenerator.hashTokenValue(authorizationCode));
    }
}
