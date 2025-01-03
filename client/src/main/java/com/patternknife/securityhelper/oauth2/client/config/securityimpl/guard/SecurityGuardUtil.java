package com.patternknife.securityhelper.oauth2.client.config.securityimpl.guard;

import com.patternknife.securityhelper.oauth2.client.config.securityimpl.guard.AccessTokenUserInfo;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionAuthenticatedPrincipal;

public class SecurityGuardUtil {


    public static AccessTokenUserInfo getAccessTokenUser(){

        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();

        String userName =((OAuth2IntrospectionAuthenticatedPrincipal)principal).getAttribute("username");

        if (principal instanceof AccessTokenUserInfo) {
            return ((AccessTokenUserInfo) principal);
        }

        return null;
    }


}
