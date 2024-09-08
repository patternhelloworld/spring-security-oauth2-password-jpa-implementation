package com.patternknife.securityhelper.oauth2.client.domain.traditionaloauth.api.v1;


import com.github.patternknife.securityhelper.oauth2.api.config.security.response.error.exception.KnifeOauth2AuthenticationException;
import com.github.patternknife.securityhelper.oauth2.api.config.security.message.DefaultSecurityUserExceptionMessage;

import com.github.patternknife.securityhelper.oauth2.api.config.security.message.ISecurityUserExceptionMessageService;
import com.github.patternknife.securityhelper.oauth2.api.domain.traditionaloauth.dto.SpringSecurityTraditionalOauthDTO;
import com.github.patternknife.securityhelper.oauth2.api.domain.traditionaloauth.service.TraditionalOauthService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1")
@RequiredArgsConstructor
public class TraditionalOauthApi {

    private final TraditionalOauthService traditionalOauthService;
    private final ISecurityUserExceptionMessageService iSecurityUserExceptionMessageService;

    @PostMapping("/traditional-oauth/token")
    public SpringSecurityTraditionalOauthDTO.TokenResponse createAccessToken(
            @ModelAttribute SpringSecurityTraditionalOauthDTO.TokenRequest tokenRequest,
            @RequestHeader("Authorization") String authorizationHeader){
        switch(tokenRequest.getGrant_type()) {
            case "password":
                return traditionalOauthService.createAccessToken(tokenRequest, authorizationHeader);
            case "refresh_token":
                return traditionalOauthService.refreshAccessToken(tokenRequest, authorizationHeader);
            default:
                throw new KnifeOauth2AuthenticationException(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_WRONG_GRANT_TYPE));
        }
    }

}
