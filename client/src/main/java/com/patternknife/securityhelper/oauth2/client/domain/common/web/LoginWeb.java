package com.patternknife.securityhelper.oauth2.client.domain.common.web;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoginWeb {
    @GetMapping("/login")
    public String loginPage(HttpServletRequest request, Model model) {
        Object errorMessages = request.getAttribute("errorMessages");
        if (errorMessages != null) {
            model.addAttribute("errorMessages", errorMessages);
        }
        return "login";
    }
}
