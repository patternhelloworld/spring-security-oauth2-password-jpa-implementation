package com.github.patternknife.securityhelper.oauth2.api.config.security.serivce.userdetail;

import org.springframework.security.core.userdetails.UserDetailsService;

public interface UserDetailsServiceFactory {
    UserDetailsService getUserDetailsService(String clientId);
}
