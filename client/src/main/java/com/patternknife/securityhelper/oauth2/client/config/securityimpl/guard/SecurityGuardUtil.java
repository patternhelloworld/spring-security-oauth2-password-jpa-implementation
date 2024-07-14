package com.patternknife.securityhelper.oauth2.client.config.securityimpl.guard;

import com.patternknife.securityhelper.oauth2.client.config.securityimpl.guard.AccessTokenUserInfo;
import org.springframework.security.core.context.SecurityContextHolder;

public class SecurityGuardUtil {


    public static AccessTokenUserInfo getAccessTokenUser(){

        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();

        if (principal instanceof AccessTokenUserInfo) {
            return ((AccessTokenUserInfo) principal);
        }

        return null;
    }


}
