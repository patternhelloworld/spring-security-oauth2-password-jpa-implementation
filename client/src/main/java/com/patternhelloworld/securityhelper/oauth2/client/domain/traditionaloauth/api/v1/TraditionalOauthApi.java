package com.patternhelloworld.securityhelper.oauth2.client.domain.traditionaloauth.api.v1;


import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.response.error.exception.EasyPlusOauth2AuthenticationException;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.message.DefaultSecurityUserExceptionMessage;

import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.message.ISecurityUserExceptionMessageService;
import io.github.patternhelloworld.securityhelper.oauth2.api.domain.traditionaloauth.dto.SpringSecurityTraditionalOauthDTO;
import io.github.patternhelloworld.securityhelper.oauth2.api.domain.traditionaloauth.service.TraditionalOauthService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
public class TraditionalOauthApi {

    private final TraditionalOauthService traditionalOauthService;
    private final ISecurityUserExceptionMessageService iSecurityUserExceptionMessageService;

    @PostMapping("/api/v1/traditional-oauth/token")
    public SpringSecurityTraditionalOauthDTO.TokenResponse createAccessToken(
            @ModelAttribute SpringSecurityTraditionalOauthDTO.TokenRequest tokenRequest,
            @RequestHeader("Authorization") String authorizationHeader){
        switch(tokenRequest.getGrant_type()) {
            case "password":
                return traditionalOauthService.createAccessToken(tokenRequest, authorizationHeader);
            case "refresh_token":
                return traditionalOauthService.refreshAccessToken(tokenRequest, authorizationHeader);
            default:
                throw new EasyPlusOauth2AuthenticationException(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_WRONG_GRANT_TYPE));
        }
    }

/*    @PostMapping("/api/v1/traditional-oauth/authorization-code")
    public SpringSecurityTraditionalOauthDTO.AuthorizationCodeResponse createAuthorizationCode(
            @ModelAttribute SpringSecurityTraditionalOauthDTO.AuthorizationCodeRequest authorizationCodeRequest,
            @RequestHeader("Authorization") String authorizationHeader){

        // authorization_code 생성
        return traditionalOauthService.createAuthorizationCode(authorizationCodeRequest, authorizationHeader);
    }*/

}
