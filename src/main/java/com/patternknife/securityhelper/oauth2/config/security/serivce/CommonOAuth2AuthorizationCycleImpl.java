package com.patternknife.securityhelper.oauth2.config.security.serivce;

import com.patternknife.securityhelper.oauth2.config.CustomHttpHeaders;
import com.patternknife.securityhelper.oauth2.config.logger.module.NonStopErrorLogConfig;
import com.patternknife.securityhelper.oauth2.config.response.error.exception.auth.UnauthenticatedException;
import com.patternknife.securityhelper.oauth2.config.security.serivce.authentication.OAuth2AuthorizationBuildingService;
import com.patternknife.securityhelper.oauth2.config.security.serivce.persistence.authorization.OAuth2AuthorizationServiceImpl;
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

     private static final Logger logger = LoggerFactory.getLogger(NonStopErrorLogConfig.class);

     private final OAuth2AuthorizationBuildingService oAuth2AuthorizationBuildingService;
     private final OAuth2AuthorizationServiceImpl oAuth2AuthorizationService;

     @Override
     public OAuth2Authorization run(UserDetails userDetails, AuthorizationGrantType authorizationGrantType, String clientId,
                                                                   Map<String, Object> additionalParameters) {

          OAuth2Authorization oAuth2Authorization = oAuth2AuthorizationService.findByUserNameAndClientIdAndAppToken(userDetails.getUsername(), clientId, (String) additionalParameters.get(CustomHttpHeaders.APP_TOKEN));
          if(((String)additionalParameters.get("grant_type")).equals(AuthorizationGrantType.PASSWORD.getValue())){
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
          }else if(((String)additionalParameters.get("grant_type")).equals(AuthorizationGrantType.REFRESH_TOKEN.getValue())){
               int retryLogin = 0;
               while (retryLogin < 5) {
                    try {

                         OAuth2Authorization oAuth2AuthorizationFromRefreshToken = oAuth2AuthorizationService.findByToken((String)additionalParameters.get("refresh_token"), OAuth2TokenType.REFRESH_TOKEN);

                         if(oAuth2AuthorizationFromRefreshToken == null){
                              throw new UnauthenticatedException("Refresh Token Expired.");
                         }
                         if(oAuth2AuthorizationFromRefreshToken.getRefreshToken() == null || oAuth2AuthorizationFromRefreshToken.getRefreshToken().isExpired()){
                              oAuth2AuthorizationService.remove(oAuth2AuthorizationFromRefreshToken);
                              throw new UnauthenticatedException("Refresh Token Expired.");
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

          }


          return oAuth2Authorization;

     }
}
