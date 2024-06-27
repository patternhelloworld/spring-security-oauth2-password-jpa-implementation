package com.patternknife.securityhelper.oauth2.domain.traditionaloauth.api.v1;


import com.patternknife.securityhelper.oauth2.config.response.GlobalSuccessPayload;
import com.patternknife.securityhelper.oauth2.config.response.error.message.SecurityUserExceptionMessage;
import com.patternknife.securityhelper.oauth2.domain.traditionaloauth.dto.SpringSecurityTraditionalOauthDTO;
import com.patternknife.securityhelper.oauth2.domain.traditionaloauth.service.TraditionalOauthService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@RestController
@RequestMapping("/api/v1")
@RequiredArgsConstructor
public class TraditionalOauthApi {

    private final TraditionalOauthService traditionalOauthService;

    @PostMapping("/traditional-oauth/token")
    public GlobalSuccessPayload<SpringSecurityTraditionalOauthDTO.TokenResponse> createAccessToken(
            @ModelAttribute SpringSecurityTraditionalOauthDTO.TokenRequest tokenRequest,
            @RequestHeader("Authorization") String authorizationHeader) throws IOException {
        switch(tokenRequest.getGrant_type()) {
            case "password":
                return new GlobalSuccessPayload<>(traditionalOauthService.createAccessToken(tokenRequest, authorizationHeader));
            case "refresh_token":
                return new GlobalSuccessPayload<>(traditionalOauthService.refreshAccessToken(tokenRequest, authorizationHeader));
            default:
                throw new IllegalStateException(SecurityUserExceptionMessage.WRONG_GRANT_TYPE.getMessage());
        }
    }

}
