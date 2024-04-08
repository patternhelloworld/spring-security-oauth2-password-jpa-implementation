package com.patternknife.securityhelper.oauth2.config.security.serivce.authentication;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;

import java.util.Map;

/*
*    Create = Build + Persist
* */
public interface OAuth2AuthorizationBuildingService {

     OAuth2Authorization build(UserDetails userDetails, AuthorizationGrantType grantType, String clientId,
                               Map<String, Object> additionalParameters, OAuth2RefreshToken shouldBePreservedRefreshToken);

}
