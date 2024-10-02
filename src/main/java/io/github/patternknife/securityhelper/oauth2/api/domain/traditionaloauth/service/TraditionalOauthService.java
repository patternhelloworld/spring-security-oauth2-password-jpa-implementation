package io.github.patternknife.securityhelper.oauth2.api.domain.traditionaloauth.service;

import io.github.patternknife.securityhelper.oauth2.api.config.logger.KnifeSecurityLogConfig;
import io.github.patternknife.securityhelper.oauth2.api.config.security.response.error.dto.ErrorMessages;
import io.github.patternknife.securityhelper.oauth2.api.config.security.response.error.exception.KnifeOauth2AuthenticationException;

import io.github.patternknife.securityhelper.oauth2.api.config.security.message.DefaultSecurityUserExceptionMessage;
import io.github.patternknife.securityhelper.oauth2.api.config.security.message.ISecurityUserExceptionMessageService;
import io.github.patternknife.securityhelper.oauth2.api.config.security.serivce.CommonOAuth2AuthorizationSaver;
import io.github.patternknife.securityhelper.oauth2.api.config.security.serivce.DefaultOauth2AuthenticationHashCheckService;
import io.github.patternknife.securityhelper.oauth2.api.config.security.serivce.persistence.authorization.OAuth2AuthorizationServiceImpl;
import io.github.patternknife.securityhelper.oauth2.api.config.security.serivce.persistence.client.RegisteredClientRepositoryImpl;
import io.github.patternknife.securityhelper.oauth2.api.config.security.serivce.userdetail.ConditionalDetailsService;
import io.github.patternknife.securityhelper.oauth2.api.config.util.RequestOAuth2Distiller;
import io.github.patternknife.securityhelper.oauth2.api.domain.traditionaloauth.bo.BasicTokenResolver;
import io.github.patternknife.securityhelper.oauth2.api.domain.traditionaloauth.dto.SpringSecurityTraditionalOauthDTO;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.constraints.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;


@Service
public class TraditionalOauthService {

    private static final Logger logger = LoggerFactory.getLogger(KnifeSecurityLogConfig.class);

    private final RegisteredClientRepositoryImpl registeredClientRepository;

    private final OAuth2AuthorizationServiceImpl authorizationService;

    private final ConditionalDetailsService conditionalDetailsService;

    private final CommonOAuth2AuthorizationSaver commonOAuth2AuthorizationSaver;
    private final DefaultOauth2AuthenticationHashCheckService oauth2AuthenticationHashCheckService;


    private final ISecurityUserExceptionMessageService iSecurityUserExceptionMessageService;

    public TraditionalOauthService(RegisteredClientRepositoryImpl registeredClientRepository,
                                   OAuth2AuthorizationServiceImpl authorizationService,
                                   ConditionalDetailsService conditionalDetailsService,
                                   CommonOAuth2AuthorizationSaver commonOAuth2AuthorizationSaver,
                                   DefaultOauth2AuthenticationHashCheckService oauth2AuthenticationHashCheckService,
                                   ISecurityUserExceptionMessageService iSecurityUserExceptionMessageService) {

        this.registeredClientRepository = registeredClientRepository;
        this.authorizationService = authorizationService;
        this.conditionalDetailsService = conditionalDetailsService;

        this.commonOAuth2AuthorizationSaver = commonOAuth2AuthorizationSaver;
        this.oauth2AuthenticationHashCheckService = oauth2AuthenticationHashCheckService;

        this.iSecurityUserExceptionMessageService = iSecurityUserExceptionMessageService;

    }


    public SpringSecurityTraditionalOauthDTO.TokenResponse createAccessToken(SpringSecurityTraditionalOauthDTO.TokenRequest accessTokenRequest,
                                                                             String authorizationHeader) throws KnifeOauth2AuthenticationException {
        try {
            BasicTokenResolver.BasicCredentials basicCredentials = BasicTokenResolver.parse(authorizationHeader).orElseThrow(() -> new KnifeOauth2AuthenticationException(ErrorMessages.builder().message("Header parsing error (header : " + authorizationHeader).userMessage(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_WRONG_CLIENT_ID_SECRET)).build()));

            HttpServletRequest request =
                    ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();

            @NotNull RegisteredClient registeredClient = registeredClientRepository.findByClientId(basicCredentials.getClientId());

            oauth2AuthenticationHashCheckService.validateClientCredentials(basicCredentials.getClientSecret(), registeredClient);

            @NotNull UserDetails userDetails = conditionalDetailsService.loadUserByUsername(accessTokenRequest.getUsername(), basicCredentials.getClientId());

            oauth2AuthenticationHashCheckService.validateUsernamePassword(accessTokenRequest.getPassword(), userDetails);


            @NotNull OAuth2Authorization oAuth2Authorization = commonOAuth2AuthorizationSaver.save(userDetails,
                    new AuthorizationGrantType(accessTokenRequest.getGrant_type()), basicCredentials.getClientId(), RequestOAuth2Distiller.getTokenUsingSecurityAdditionalParameters(request), null);

            Instant now = Instant.now();
            Instant expiresAt = oAuth2Authorization.getAccessToken().getToken().getExpiresAt();
            int accessTokenRemainingSeconds = Math.toIntExact(Duration.between(now, expiresAt).getSeconds());

            return new SpringSecurityTraditionalOauthDTO.TokenResponse(
                    oAuth2Authorization.getAccessToken().getToken().getTokenValue(), OAuth2AccessToken.TokenType.BEARER.getValue(), Objects.requireNonNull(oAuth2Authorization.getRefreshToken()).getToken().getTokenValue(),
                    accessTokenRemainingSeconds,
                    String.join(" ", registeredClient.getScopes()));

        } catch (UsernameNotFoundException e) {
            throw new KnifeOauth2AuthenticationException(ErrorMessages.builder().message(e.getMessage()).userMessage(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_LOGIN_FAILURE)).build());
        } catch (KnifeOauth2AuthenticationException e) {
            throw e;
        } catch (Exception e) {
            throw new KnifeOauth2AuthenticationException(ErrorMessages.builder().message(e.getMessage()).userMessage(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_LOGIN_ERROR)).build());
        }
    }

    public SpringSecurityTraditionalOauthDTO.TokenResponse refreshAccessToken(SpringSecurityTraditionalOauthDTO.TokenRequest refreshTokenRequest,
                                                                              String authorizationHeader) throws KnifeOauth2AuthenticationException {
        try {
            BasicTokenResolver.BasicCredentials basicCredentials = BasicTokenResolver.parse(authorizationHeader).orElseThrow(() -> new KnifeOauth2AuthenticationException(ErrorMessages.builder().message("Header parsing error (header : " + authorizationHeader).userMessage(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_WRONG_CLIENT_ID_SECRET)).build()));

            RegisteredClient registeredClient = registeredClientRepository.findByClientId(basicCredentials.getClientId());

            OAuth2Authorization oAuth2Authorization = authorizationService.findByToken(refreshTokenRequest.getRefresh_token(), OAuth2TokenType.REFRESH_TOKEN);

            UserDetails userDetails;
            if (oAuth2Authorization == null || oAuth2Authorization.getRefreshToken() == null) {
                throw new KnifeOauth2AuthenticationException(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_LOGIN_ERROR));
            } else {
                userDetails = conditionalDetailsService.loadUserByUsername(oAuth2Authorization.getPrincipalName(), registeredClient.getClientId());
            }

            Map<String, Object> modifiableAdditionalParameters = new HashMap<>();
            modifiableAdditionalParameters.put("refresh_token", refreshTokenRequest.getRefresh_token());

            oAuth2Authorization = commonOAuth2AuthorizationSaver.save(userDetails,
                    new AuthorizationGrantType(refreshTokenRequest.getGrant_type()),
                    basicCredentials.getClientId(), oAuth2Authorization.getAttributes(), modifiableAdditionalParameters);


            Instant now = Instant.now();
            Instant expiresAt = oAuth2Authorization.getRefreshToken().getToken().getExpiresAt();
            int refreshTokenRemainingSeconds = Math.toIntExact(Duration.between(now, expiresAt).getSeconds());

            return new SpringSecurityTraditionalOauthDTO.TokenResponse(
                    oAuth2Authorization.getAccessToken().getToken().getTokenValue(), OAuth2AccessToken.TokenType.BEARER.getValue(), Objects.requireNonNull(oAuth2Authorization.getRefreshToken()).getToken().getTokenValue(),
                    refreshTokenRemainingSeconds,
                    String.join(" ", registeredClient.getScopes()));

        }catch (UsernameNotFoundException e){
            throw new KnifeOauth2AuthenticationException(ErrorMessages.builder().message(e.getMessage()).userMessage(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_LOGIN_FAILURE)).build());
        }catch (KnifeOauth2AuthenticationException e){
            throw e;
        }  catch (Exception e){
            throw new KnifeOauth2AuthenticationException(ErrorMessages.builder().message(e.getMessage()).userMessage(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_LOGIN_ERROR)).build());
        }
    }


    public SpringSecurityTraditionalOauthDTO.AuthorizationCodeResponse createAuthorizationCode(SpringSecurityTraditionalOauthDTO.AuthorizationCodeRequest authorizationCodeRequest,
                                                                                               String authorizationHeader) throws KnifeOauth2AuthenticationException {
        try {

            BasicTokenResolver.BasicCredentials basicCredentials = BasicTokenResolver.parse(authorizationHeader)
                    .orElseThrow(() -> new KnifeOauth2AuthenticationException(
                            ErrorMessages.builder()
                                    .message("Header parsing error (header : " + authorizationHeader + ")")
                                    .userMessage(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_WRONG_CLIENT_ID_SECRET))
                                    .build()));

            HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();

            // Registered Client 검증
            @NotNull RegisteredClient registeredClient = registeredClientRepository.findByClientId(basicCredentials.getClientId());
            oauth2AuthenticationHashCheckService.validateClientCredentials(basicCredentials.getClientSecret(), registeredClient);

            // UserDetails 로드 및 Username/Password 검증
            @NotNull UserDetails userDetails = conditionalDetailsService.loadUserByUsername(authorizationCodeRequest.getUsername(), basicCredentials.getClientId());
            oauth2AuthenticationHashCheckService.validateUsernamePassword(authorizationCodeRequest.getPassword(), userDetails);

            // Authorization Code 생성 및 저장
            Map<String, Object> additionalParameters = RequestOAuth2Distiller.getTokenUsingSecurityAdditionalParameters(request);
            additionalParameters.put(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.AUTHORIZATION_CODE.getValue());
            @NotNull OAuth2Authorization oAuth2Authorization = commonOAuth2AuthorizationSaver.save(userDetails, AuthorizationGrantType.AUTHORIZATION_CODE, basicCredentials.getClientId(), additionalParameters, null);

            // Authorization Code 추출
            String authorizationCode = oAuth2Authorization.getToken(OAuth2AuthorizationCode.class).getToken().getTokenValue();

            // Authorization Code Response 반환
            return new SpringSecurityTraditionalOauthDTO.AuthorizationCodeResponse(authorizationCode);

        } catch (UsernameNotFoundException e) {
            throw new KnifeOauth2AuthenticationException(
                    ErrorMessages.builder().message(e.getMessage())
                            .userMessage(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_LOGIN_FAILURE))
                            .build());
        } catch (KnifeOauth2AuthenticationException e) {
            throw e;
        } catch (Exception e) {
            throw new KnifeOauth2AuthenticationException(
                    ErrorMessages.builder().message(e.getMessage())
                            .userMessage(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_LOGIN_ERROR))
                            .build());
        }
    }


}
