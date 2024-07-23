package com.patternknife.securityhelper.oauth2.client.config.securityimpl.serivce.permission;

import io.github.patternknife.securityhelper.oauth2.api.config.security.response.error.exception.KnifeOauth2AuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Service
public class CustomAuthorityService {

    public boolean hasAnyUserRole() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if(authentication == null){
            throw new KnifeOauth2AuthenticationException();
        }
        if (authentication.getAuthorities() == null) {
            return false;
        }
        return authentication.getAuthorities().stream()
                .anyMatch(authority -> authority.getAuthority().endsWith("_USER"));
    }

}