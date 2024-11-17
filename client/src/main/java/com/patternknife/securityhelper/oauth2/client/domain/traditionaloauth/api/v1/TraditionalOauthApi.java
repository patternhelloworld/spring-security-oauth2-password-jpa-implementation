package com.patternknife.securityhelper.oauth2.client.domain.traditionaloauth.api.v1;


import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.util.Base64;
import io.github.patternknife.securityhelper.oauth2.api.config.security.response.error.exception.KnifeOauth2AuthenticationException;
import io.github.patternknife.securityhelper.oauth2.api.config.security.message.DefaultSecurityUserExceptionMessage;

import io.github.patternknife.securityhelper.oauth2.api.config.security.message.ISecurityUserExceptionMessageService;
import io.github.patternknife.securityhelper.oauth2.api.domain.traditionaloauth.dto.SpringSecurityTraditionalOauthDTO;
import io.github.patternknife.securityhelper.oauth2.api.domain.traditionaloauth.service.TraditionalOauthService;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.ToString;
import org.springframework.http.*;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

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
                throw new KnifeOauth2AuthenticationException(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_WRONG_GRANT_TYPE));
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
