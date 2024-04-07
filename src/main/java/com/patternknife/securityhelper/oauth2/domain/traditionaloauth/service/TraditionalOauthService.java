package com.patternknife.securityhelper.oauth2.domain.traditionaloauth.service;

import com.patternknife.securityhelper.oauth2.config.logger.module.NonStopErrorLogConfig;
import com.patternknife.securityhelper.oauth2.config.response.error.message.SecurityExceptionMessage;
import com.patternknife.securityhelper.oauth2.config.response.error.exception.auth.UnauthorizedException;
import com.patternknife.securityhelper.oauth2.config.security.OAuth2ClientCachedInfo;
import com.patternknife.securityhelper.oauth2.config.security.principal.AccessTokenUserInfo;
import com.patternknife.securityhelper.oauth2.config.security.serivce.CommonOAuth2AuthorizationCycle;
import com.patternknife.securityhelper.oauth2.config.security.serivce.OAuth2AuthorizationServiceImpl;
import com.patternknife.securityhelper.oauth2.config.security.serivce.Oauth2AuthenticationService;
import com.patternknife.securityhelper.oauth2.config.security.serivce.userdetail.ConditionalDetailsService;
import com.patternknife.securityhelper.oauth2.config.security.util.SecurityUtil;
import com.patternknife.securityhelper.oauth2.domain.traditionaloauth.bo.BasicTokenResolver;
import com.patternknife.securityhelper.oauth2.domain.traditionaloauth.dto.SpringSecurityTraditionalOauthDTO;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;


@Service
public class TraditionalOauthService {

    private static final Logger logger = LoggerFactory.getLogger(NonStopErrorLogConfig.class);

    private final RegisteredClientRepository registeredClientRepository;

    private final OAuth2AuthorizationServiceImpl authorizationService;

    private final ConditionalDetailsService conditionalDetailsService;

    private final CommonOAuth2AuthorizationCycle commonOAuth2AuthorizationCycle;
    private final Oauth2AuthenticationService oauth2AuthenticationService;


    public TraditionalOauthService(RegisteredClientRepository registeredClientRepository,
                                   OAuth2AuthorizationServiceImpl authorizationService,
                                   ConditionalDetailsService conditionalDetailsService,
                                   CommonOAuth2AuthorizationCycle commonOAuth2AuthorizationCycle,
                                   Oauth2AuthenticationService oauth2AuthenticationService) {

        this.registeredClientRepository = registeredClientRepository;
        this.authorizationService = authorizationService;
        this.conditionalDetailsService = conditionalDetailsService;

        this.commonOAuth2AuthorizationCycle = commonOAuth2AuthorizationCycle;
        this.oauth2AuthenticationService = oauth2AuthenticationService;

    }


    public SpringSecurityTraditionalOauthDTO.TokenResponse createAccessToken(SpringSecurityTraditionalOauthDTO.TokenRequest accessTokenRequest,
                                                                             String authorizationHeader) {

        BasicTokenResolver.BasicCredentials basicCredentials = BasicTokenResolver.parse(authorizationHeader).orElseThrow(UnauthorizedException::new);

        UserDetails userDetails = conditionalDetailsService.loadUserByUsername(accessTokenRequest.getUsername(), basicCredentials.getClientId());

        if(basicCredentials.getClientId().equals(OAuth2ClientCachedInfo.ADMIN_CLIENT_ID.getValue())){
            oauth2AuthenticationService.validateOtpValue(accessTokenRequest.getOtp_value(),((AccessTokenUserInfo) userDetails).getAdditionalAccessTokenUserInfo().getOtpSecretKey());
        }

        oauth2AuthenticationService.validatePassword(accessTokenRequest.getPassword(), userDetails);

        HttpServletRequest request =
                ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();

        OAuth2Authorization oAuth2Authorization = commonOAuth2AuthorizationCycle.run(userDetails,
                new AuthorizationGrantType(accessTokenRequest.getGrant_type()), basicCredentials.getClientId(), SecurityUtil.getTokenUsingSecurityAdditionalParameters(request));

        Instant now = Instant.now();
        Instant expiresAt = oAuth2Authorization.getAccessToken().getToken().getExpiresAt();
        int accessTokenRemainingSeconds = Math.toIntExact(Duration.between(now, expiresAt).getSeconds());

        return new SpringSecurityTraditionalOauthDTO.TokenResponse(
                oAuth2Authorization.getAccessToken().getToken().getTokenValue(), OAuth2AccessToken.TokenType.BEARER.getValue(), Objects.requireNonNull(oAuth2Authorization.getRefreshToken()).getToken().getTokenValue(),
                accessTokenRemainingSeconds,
                String.join(" ", Objects.requireNonNull(OAuth2ClientCachedInfo.getScopeByValue(basicCredentials.getClientId()))));
    }

    public SpringSecurityTraditionalOauthDTO.TokenResponse refreshAccessToken(SpringSecurityTraditionalOauthDTO.TokenRequest refreshTokenRequest,
                                                                              String authorizationHeader) throws IOException {

        BasicTokenResolver.BasicCredentials basicCredentials = BasicTokenResolver.parse(authorizationHeader).orElseThrow(()-> new UnauthorizedException("Header Token 의 파싱에 실패 하였습니다."));

        RegisteredClient registeredClient = registeredClientRepository.findByClientId(basicCredentials.getClientId());

        assert registeredClient != null;

        if(!(basicCredentials.getClientId().equals(registeredClient.getClientId())
                && oauth2AuthenticationService.validateClientCredentials(basicCredentials.getClientSecret(), registeredClient))) {
            throw new UnauthorizedException(SecurityExceptionMessage.AUTHORIZATION_ERROR.getMessage());
        }

        OAuth2Authorization oAuth2Authorization = authorizationService.findByToken(refreshTokenRequest.getRefresh_token(), OAuth2TokenType.REFRESH_TOKEN);
        // 리프레시 토큰 검증
        if (oAuth2Authorization == null || oAuth2Authorization.getRefreshToken() == null) {
            throw new InvalidBearerTokenException("유효하지 않은 Refresh Token 입니다. 문제가 지속된다면 관리자에게 문의 하십시오.");
        }

        // Overwrite Access + Refresh Tokens
        authorizationService.save(oAuth2Authorization);

        Instant now = Instant.now();
        Instant expiresAt = oAuth2Authorization.getRefreshToken().getToken().getExpiresAt();
        int refreshTokenRemainingSeconds = Math.toIntExact(Duration.between(now, expiresAt).getSeconds());

        return new SpringSecurityTraditionalOauthDTO.TokenResponse(
                oAuth2Authorization.getAccessToken().getToken().getTokenValue(), OAuth2AccessToken.TokenType.BEARER.getValue(), Objects.requireNonNull(oAuth2Authorization.getRefreshToken()).getToken().getTokenValue(),
                refreshTokenRemainingSeconds,
                String.join(" ", registeredClient.getScopes()));
    }

}
