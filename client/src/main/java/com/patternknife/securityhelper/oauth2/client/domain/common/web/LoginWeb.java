package com.patternknife.securityhelper.oauth2.client.domain.common.web;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoginWeb {
    @GetMapping("/login")
    public String loginPage() {
        return "login";
    }
}
