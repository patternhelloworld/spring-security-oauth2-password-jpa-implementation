package io.github.patternknife.securityhelper.oauth2.api.config.security.serivce;


import io.github.patternknife.securityhelper.oauth2.api.config.logger.KnifeSecurityLogConfig;
import io.github.patternknife.securityhelper.oauth2.api.config.security.message.DefaultSecurityUserExceptionMessage;
import io.github.patternknife.securityhelper.oauth2.api.config.security.message.ISecurityUserExceptionMessageService;
import io.github.patternknife.securityhelper.oauth2.api.config.security.response.error.dto.ErrorMessages;
import io.github.patternknife.securityhelper.oauth2.api.config.security.response.error.exception.KnifeOauth2AuthenticationException;
import io.github.patternknife.securityhelper.oauth2.api.config.util.KnifeHttpHeaders;
import io.github.patternknife.securityhelper.oauth2.api.config.security.serivce.authentication.OAuth2AuthorizationBuildingService;
import io.github.patternknife.securityhelper.oauth2.api.config.security.serivce.persistence.authorization.OAuth2AuthorizationServiceImpl;

import io.github.patternknife.securityhelper.oauth2.api.config.util.SecurityExceptionUtils;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.stereotype.Service;

import java.util.Map;


@Service
@RequiredArgsConstructor
public class CommonOAuth2AuthorizationSaverImpl implements CommonOAuth2AuthorizationSaver {

     private static final Logger logger = LoggerFactory.getLogger(KnifeSecurityLogConfig.class);

     private final OAuth2AuthorizationBuildingService oAuth2AuthorizationBuildingService;
     private final OAuth2AuthorizationServiceImpl oAuth2AuthorizationService;
     private final ISecurityUserExceptionMessageService iSecurityUserExceptionMessageService;

     /*
      *  While the Spring Authorization Server is generally not expected to cause duplicate exceptions,
      *  I have observed such errors in the past. This is a preventive measure to handle potential issues gracefully.
      */
     @Override
     public @NotNull OAuth2Authorization save(UserDetails userDetails, AuthorizationGrantType authorizationGrantType, String clientId,
                                              Map<String, Object> additionalParameters, Map<String, Object> modifiableAdditionalParameters) {

          if (authorizationGrantType.getValue().equals(AuthorizationGrantType.AUTHORIZATION_CODE.getValue())) {
               return SecurityExceptionUtils.retryOnDuplicateException(() -> {
                    OAuth2Authorization oAuth2Authorization = oAuth2AuthorizationBuildingService.build(
                            userDetails, authorizationGrantType, clientId, additionalParameters, null);
                    oAuth2AuthorizationService.save(oAuth2Authorization);
                    return oAuth2Authorization;
               }, 5, logger, "[Authorization Code] An error occurred with the Key during the execution of persistOAuth2Authorization for " + userDetails.getUsername());

          }else {

               OAuth2Authorization oAuth2Authorization = oAuth2AuthorizationService.findByUserNameAndClientIdAndAppToken(
                       userDetails.getUsername(), clientId, (String) additionalParameters.get(KnifeHttpHeaders.APP_TOKEN));

               if (authorizationGrantType.getValue().equals(AuthorizationGrantType.PASSWORD.getValue())
                    || authorizationGrantType.getValue().equals(OAuth2ParameterNames.CODE)) {

                    if(authorizationGrantType.getValue().equals(OAuth2ParameterNames.CODE)){
                         OAuth2Authorization oAuth2AuthorizationForCodeVerification = oAuth2AuthorizationService.findByAuthorizationCode(additionalParameters.get(OAuth2ParameterNames.CODE).toString());
                         if(oAuth2AuthorizationForCodeVerification == null) {
                              throw new KnifeOauth2AuthenticationException("No authorization code found");
                         }else{
                              OAuth2Authorization.Token oAuth2Token =oAuth2AuthorizationForCodeVerification.getToken(OAuth2AuthorizationCode.class);
                              if(oAuth2Token == null){
                                   throw new KnifeOauth2AuthenticationException("No authorization code found2");
                              }
                              if(oAuth2Token.isExpired()){
                                   throw new KnifeOauth2AuthenticationException("authorization code expired");
                              }
                         }
                    }

                    if (oAuth2Authorization == null || oAuth2Authorization.getAccessToken().isExpired()) {
                         return SecurityExceptionUtils.retryOnDuplicateException(() -> {
                              OAuth2Authorization authorization = oAuth2AuthorizationBuildingService.build(
                                      userDetails, authorizationGrantType, clientId, additionalParameters, null);
                              oAuth2AuthorizationService.save(authorization);
                              return authorization;
                         }, 5, logger, "[Access Token] An error occurred with the Key during the execution of persistOAuth2Authorization for " + userDetails.getUsername());
                    }
               } else if (authorizationGrantType.getValue().equals(AuthorizationGrantType.REFRESH_TOKEN.getValue())) {
                    return SecurityExceptionUtils.retryOnDuplicateException(() -> {
                         String refreshTokenValue = (String) (additionalParameters.containsKey("refresh_token") ? additionalParameters.get("refresh_token")
                                 : modifiableAdditionalParameters.get("refresh_token"));

                         OAuth2Authorization oAuth2AuthorizationFromRefreshToken = oAuth2AuthorizationService.findByToken(refreshTokenValue, OAuth2TokenType.REFRESH_TOKEN);

                         if (oAuth2AuthorizationFromRefreshToken == null || oAuth2AuthorizationFromRefreshToken.getRefreshToken().isExpired()) {
                              oAuth2AuthorizationService.remove(oAuth2AuthorizationFromRefreshToken);
                              throw new KnifeOauth2AuthenticationException("Refresh Token Expired.");
                         }

                         OAuth2RefreshToken shouldBePreservedRefreshToken = oAuth2AuthorizationFromRefreshToken.getRefreshToken().getToken();
                         oAuth2AuthorizationService.remove(oAuth2AuthorizationFromRefreshToken);

                         OAuth2Authorization authorization = oAuth2AuthorizationBuildingService.build(
                                 userDetails, authorizationGrantType, clientId, additionalParameters, shouldBePreservedRefreshToken);
                         oAuth2AuthorizationService.save(authorization);
                         return authorization;

                    }, 5, logger, "[Refresh Token] An error occurred with the Key during the execution of persistOAuth2Authorization for " + userDetails.getUsername());
               } else {
                    throw new KnifeOauth2AuthenticationException(ErrorMessages.builder().message("Wrong grant type from Req : " + authorizationGrantType.getValue()).userMessage(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_WRONG_GRANT_TYPE)).build());
               }

               return oAuth2Authorization;
          }
     }
}

