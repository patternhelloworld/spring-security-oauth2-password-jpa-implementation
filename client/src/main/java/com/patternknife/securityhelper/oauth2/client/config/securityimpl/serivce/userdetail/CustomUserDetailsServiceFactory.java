package com.patternknife.securityhelper.oauth2.client.config.securityimpl.serivce.userdetail;


import io.github.patternknife.securityhelper.oauth2.api.config.security.serivce.userdetail.UserDetailsServiceFactory;
import com.patternknife.securityhelper.oauth2.client.config.securityimpl.guard.AdditionalAccessTokenUserInfo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class CustomUserDetailsServiceFactory implements UserDetailsServiceFactory {

    private final Map<String, UserDetailsService> userDetailsServiceMap;

    @Autowired
    public CustomUserDetailsServiceFactory(List<UserDetailsService> userDetailsServices) {
        userDetailsServiceMap = new HashMap<>();
        for (UserDetailsService userDetailsService : userDetailsServices) {
            if (userDetailsService instanceof AdminDetailsService) {
                userDetailsServiceMap.put(AdditionalAccessTokenUserInfo.UserType.ADMIN.getValue(), userDetailsService);
            } else if (userDetailsService instanceof CustomerDetailsService) {
                userDetailsServiceMap.put(AdditionalAccessTokenUserInfo.UserType.CUSTOMER.getValue(), userDetailsService);
            }
        }
    }

    @Override
    public UserDetailsService getUserDetailsService(String clientId) {
        return userDetailsServiceMap.get(clientId);
    }
}
