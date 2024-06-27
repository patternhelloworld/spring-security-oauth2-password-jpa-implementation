package com.patternknife.securityhelper.oauth2.domain.traditionaloauth.service;

import com.patternknife.securityhelper.oauth2.config.logger.module.NonStopErrorLogConfig;
import com.patternknife.securityhelper.oauth2.config.response.error.exception.auth.CustomOauth2AuthenticationException;
import com.patternknife.securityhelper.oauth2.config.response.error.exception.auth.UnauthorizedException;
import com.patternknife.securityhelper.oauth2.config.response.error.message.SecurityUserExceptionMessage;
import com.patternknife.securityhelper.oauth2.config.security.OAuth2ClientCachedInfo;
import com.patternknife.securityhelper.oauth2.config.security.serivce.CommonOAuth2AuthorizationCycle;
import com.patternknife.securityhelper.oauth2.config.security.serivce.Oauth2AuthenticationHashCheckService;
import com.patternknife.securityhelper.oauth2.config.security.serivce.persistence.authorization.OAuth2AuthorizationServiceImpl;
import com.patternknife.securityhelper.oauth2.config.security.serivce.persistence.client.RegisteredClientRepositoryImpl;
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
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;


@Service
public class TraditionalOauthService {

    private static final Logger logger = LoggerFactory.getLogger(NonStopErrorLogConfig.class);

    private final RegisteredClientRepositoryImpl registeredClientRepository;

    private final OAuth2AuthorizationServiceImpl authorizationService;

    private final ConditionalDetailsService conditionalDetailsService;

    private final CommonOAuth2AuthorizationCycle commonOAuth2AuthorizationCycle;
    private final Oauth2AuthenticationHashCheckService oauth2AuthenticationHashCheckService;


    public TraditionalOauthService(RegisteredClientRepositoryImpl registeredClientRepository,
                                   OAuth2AuthorizationServiceImpl authorizationService,
                                   ConditionalDetailsService conditionalDetailsService,
                                   CommonOAuth2AuthorizationCycle commonOAuth2AuthorizationCycle,
                                   Oauth2AuthenticationHashCheckService oauth2AuthenticationHashCheckService) {

        this.registeredClientRepository = registeredClientRepository;
        this.authorizationService = authorizationService;
        this.conditionalDetailsService = conditionalDetailsService;

        this.commonOAuth2AuthorizationCycle = commonOAuth2AuthorizationCycle;
        this.oauth2AuthenticationHashCheckService = oauth2AuthenticationHashCheckService;

    }


    public SpringSecurityTraditionalOauthDTO.TokenResponse createAccessToken(SpringSecurityTraditionalOauthDTO.TokenRequest accessTokenRequest,
                                                                             String authorizationHeader) {

        BasicTokenResolver.BasicCredentials basicCredentials = BasicTokenResolver.parse(authorizationHeader).orElseThrow(UnauthorizedException::new);

        RegisteredClient registeredClient = registeredClientRepository.findByClientId(basicCredentials.getClientId());

        oauth2AuthenticationHashCheckService.validateClientCredentials(basicCredentials.getClientSecret(), registeredClient);

        UserDetails userDetails = conditionalDetailsService.loadUserByUsername(accessTokenRequest.getUsername(), basicCredentials.getClientId());

        oauth2AuthenticationHashCheckService.validateUsernamePassword(accessTokenRequest.getPassword(), userDetails);

        HttpServletRequest request =
                ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();

        OAuth2Authorization oAuth2Authorization = commonOAuth2AuthorizationCycle.run(userDetails,
                new AuthorizationGrantType(accessTokenRequest.getGrant_type()), basicCredentials.getClientId(), SecurityUtil.getTokenUsingSecurityAdditionalParameters(request), null);

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

        BasicTokenResolver.BasicCredentials basicCredentials = BasicTokenResolver.parse(authorizationHeader).orElseThrow(()-> new UnauthorizedException(SecurityUserExceptionMessage.AUTHORIZATION_ERROR.getMessage()));

        RegisteredClient registeredClient = registeredClientRepository.findByClientId(basicCredentials.getClientId());

        OAuth2Authorization oAuth2Authorization = authorizationService.findByToken(refreshTokenRequest.getRefresh_token(), OAuth2TokenType.REFRESH_TOKEN);

        UserDetails userDetails;
        if (oAuth2Authorization == null || oAuth2Authorization.getRefreshToken() == null) {
            throw new CustomOauth2AuthenticationException(SecurityUserExceptionMessage.AUTHENTICATION_LOGIN_ERROR.getMessage());
        }else{
            userDetails = conditionalDetailsService.loadUserByUsername(oAuth2Authorization.getPrincipalName(), registeredClient.getClientId());
        }

        Map<String, Object> modifiableAdditionalParameters = new HashMap<>();
        modifiableAdditionalParameters.put("refresh_token", refreshTokenRequest.getRefresh_token());

        oAuth2Authorization = commonOAuth2AuthorizationCycle.run(userDetails,
                new AuthorizationGrantType(refreshTokenRequest.getGrant_type()),
                basicCredentials.getClientId(), oAuth2Authorization.getAttributes(), modifiableAdditionalParameters);


        Instant now = Instant.now();
        Instant expiresAt = oAuth2Authorization.getRefreshToken().getToken().getExpiresAt();
        int refreshTokenRemainingSeconds = Math.toIntExact(Duration.between(now, expiresAt).getSeconds());

        return new SpringSecurityTraditionalOauthDTO.TokenResponse(
                oAuth2Authorization.getAccessToken().getToken().getTokenValue(), OAuth2AccessToken.TokenType.BEARER.getValue(), Objects.requireNonNull(oAuth2Authorization.getRefreshToken()).getToken().getTokenValue(),
                refreshTokenRemainingSeconds,
                String.join(" ", registeredClient.getScopes()));
    }

}
