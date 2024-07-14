package com.patternknife.securityhelper.oauth2.client.domain.traditionaloauth.api.v1;


import com.patternknife.securityhelper.oauth2.api.config.response.error.exception.auth.KnifeOauth2AuthenticationException;
import com.patternknife.securityhelper.oauth2.api.config.response.error.message.SecurityUserExceptionMessage;

import com.patternknife.securityhelper.oauth2.api.domain.traditionaloauth.dto.SpringSecurityTraditionalOauthDTO;
import com.patternknife.securityhelper.oauth2.api.domain.traditionaloauth.service.TraditionalOauthService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@RestController
@RequestMapping("/api/v1")
@RequiredArgsConstructor
public class TraditionalOauthApi {

    private final TraditionalOauthService traditionalOauthService;

    @PostMapping("/traditional-oauth/token")
    public SpringSecurityTraditionalOauthDTO.TokenResponse createAccessToken(
            @ModelAttribute SpringSecurityTraditionalOauthDTO.TokenRequest tokenRequest,
            @RequestHeader("Authorization") String authorizationHeader) throws IOException {
        switch(tokenRequest.getGrant_type()) {
            case "password":
                return traditionalOauthService.createAccessToken(tokenRequest, authorizationHeader);
            case "refresh_token":
                return traditionalOauthService.refreshAccessToken(tokenRequest, authorizationHeader);
            default:
                throw new KnifeOauth2AuthenticationException(SecurityUserExceptionMessage.WRONG_GRANT_TYPE.getMessage());
        }
    }

}
