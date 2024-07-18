package io.github.patternknife.securityhelper.oauth2.api.config.security.serivce;


import io.github.patternknife.securityhelper.oauth2.api.config.logger.KnifeSecurityLogConfig;
import io.github.patternknife.securityhelper.oauth2.api.config.security.response.error.exception.KnifeOauth2AuthenticationException;
import io.github.patternknife.securityhelper.oauth2.api.config.security.util.KnifeHttpHeaders;
import io.github.patternknife.securityhelper.oauth2.api.config.security.serivce.authentication.OAuth2AuthorizationBuildingService;
import io.github.patternknife.securityhelper.oauth2.api.config.security.serivce.persistence.authorization.OAuth2AuthorizationServiceImpl;

import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.stereotype.Service;

import java.util.Map;


@Service
@RequiredArgsConstructor
public class CommonOAuth2AuthorizationCycleImpl implements CommonOAuth2AuthorizationCycle {

     private static final Logger logger = LoggerFactory.getLogger(KnifeSecurityLogConfig.class);

     private final OAuth2AuthorizationBuildingService oAuth2AuthorizationBuildingService;
     private final OAuth2AuthorizationServiceImpl oAuth2AuthorizationService;

     @Override
     public OAuth2Authorization run(UserDetails userDetails, AuthorizationGrantType authorizationGrantType, String clientId,
                                                                   Map<String, Object> additionalParameters, Map<String, Object> modifiableAdditionalParameters) {

          OAuth2Authorization oAuth2Authorization = oAuth2AuthorizationService.findByUserNameAndClientIdAndAppToken(userDetails.getUsername(), clientId, (String) additionalParameters.get(KnifeHttpHeaders.APP_TOKEN));
          if(authorizationGrantType.getValue().equals(AuthorizationGrantType.PASSWORD.getValue())){
               if (oAuth2Authorization == null || oAuth2Authorization.getAccessToken().isExpired()) {
                    int retryLogin = 0;
                    while (retryLogin < 5) {
                         try {
                              oAuth2Authorization = oAuth2AuthorizationBuildingService.build(
                                      userDetails, authorizationGrantType, clientId, additionalParameters, null);

                              oAuth2AuthorizationService.save(oAuth2Authorization);

                              return oAuth2Authorization;

                         } catch (DataIntegrityViolationException e) {

                              logger.error("An error occurred with the Key during the execution of persistOAuth2Authorization for " + userDetails.getUsername() + "... Retrying up to 5 times.... (Count: " + retryLogin + ") - " + e.getMessage());
                              retryLogin += 1;
                         }
                    }
               }
          }else if(authorizationGrantType.getValue().equals(AuthorizationGrantType.REFRESH_TOKEN.getValue())){
               int retryLogin = 0;
               while (retryLogin < 5) {
                    try {
                         String refreshTokenValue = null;
                         if(additionalParameters.containsKey("refresh_token")){
                              refreshTokenValue = (String) additionalParameters.get("refresh_token");
                         }else{
                              assert modifiableAdditionalParameters != null;
                              refreshTokenValue = (String)modifiableAdditionalParameters.get("refresh_token");
                         }
                         assert refreshTokenValue != null;


                         OAuth2Authorization oAuth2AuthorizationFromRefreshToken = oAuth2AuthorizationService.findByToken(refreshTokenValue, OAuth2TokenType.REFRESH_TOKEN);

                         if(oAuth2AuthorizationFromRefreshToken == null){
                              throw new KnifeOauth2AuthenticationException("Refresh Token Expired.");
                         }
                         if(oAuth2AuthorizationFromRefreshToken.getRefreshToken() == null || oAuth2AuthorizationFromRefreshToken.getRefreshToken().isExpired()){
                              oAuth2AuthorizationService.remove(oAuth2AuthorizationFromRefreshToken);
                              throw new KnifeOauth2AuthenticationException("Refresh Token Expired.");
                         }

                         OAuth2RefreshToken shouldBePreservedRefreshToken = oAuth2AuthorizationFromRefreshToken.getRefreshToken().getToken();

                         oAuth2AuthorizationService.remove(oAuth2AuthorizationFromRefreshToken);

                         oAuth2Authorization = oAuth2AuthorizationBuildingService.build(
                                 userDetails, authorizationGrantType, clientId, additionalParameters, shouldBePreservedRefreshToken);

                         oAuth2AuthorizationService.save(oAuth2Authorization);

                         return oAuth2Authorization;

                    } catch (DataIntegrityViolationException e) {

                         logger.error("An error occurred with the Key during the execution of persistOAuth2Authorization for " + userDetails.getUsername() + "... Retrying up to 5 times.... (Count: " + retryLogin + ") - " + e.getMessage());
                         retryLogin += 1;
                    }
               }

          }else{
               // TO DO.
          }


          return oAuth2Authorization;

     }
}
