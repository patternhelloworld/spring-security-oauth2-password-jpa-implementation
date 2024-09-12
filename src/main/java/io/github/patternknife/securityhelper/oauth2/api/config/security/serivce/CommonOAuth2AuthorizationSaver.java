package io.github.patternknife.securityhelper.oauth2.api.config.security.serivce;

import jakarta.annotation.Nullable;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;

import java.util.Map;

/*
*    Create = Build + Persist
* */
public interface CommonOAuth2AuthorizationSaver {

     OAuth2Authorization save(UserDetails userDetails, AuthorizationGrantType authorizationGrantType,
                              String clientId, Map<String, Object> additionalParameters,
                              @Nullable Map<String, Object> modifiableAdditionalParameters);

}
