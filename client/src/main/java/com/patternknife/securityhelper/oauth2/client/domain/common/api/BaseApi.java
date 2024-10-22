package com.patternknife.securityhelper.oauth2.client.domain.common.api;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class BaseApi {

    @Value("${spring.profiles.active}")
    private String activeProfile;

    @PreAuthorize("isAuthenticated()")
    @GetMapping("/systemProfile")
    public String checkAuthenticated () {
        return activeProfile;
    }

    @PreAuthorize("@customAuthorityService.hasAnyUserRole()")
    @GetMapping("/systemProfile2")
    public String checkPermissions () {
        return activeProfile;
    }



    @GetMapping("/")
    public String home () {
        return "home";
    }



}
