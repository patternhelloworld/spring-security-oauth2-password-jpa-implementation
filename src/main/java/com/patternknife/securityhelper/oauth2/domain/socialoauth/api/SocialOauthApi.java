package com.patternknife.securityhelper.oauth2.domain.socialoauth.api;


import com.patternknife.securityhelper.oauth2.config.response.GlobalSuccessPayload;
import com.patternknife.securityhelper.oauth2.domain.socialoauth.dto.SpringSecuritySocialOauthDTO;
import com.patternknife.securityhelper.oauth2.domain.socialoauth.service.SocialOauthService;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;

@RestController
@AllArgsConstructor

public class SocialOauthApi {

    private final SocialOauthService socialOauthService;

    /* 1. 카카오 */

    @PostMapping("/social-oauth/token/kakao")
    public GlobalSuccessPayload<SpringSecuritySocialOauthDTO.TokenResponse> createAccessTokenUsingKaKaoToken(
             @RequestBody final SpringSecuritySocialOauthDTO.TokenRequest tokenRequest)
            throws IOException {

        return new GlobalSuccessPayload<>(socialOauthService.getAccessTokenUsingKaKaoToken(tokenRequest));

    }

    @PostMapping("/social-oauth/token/kakao/create")
    public GlobalSuccessPayload<SpringSecuritySocialOauthDTO.CreateCustomerResponse> createKakaoUser(
            @Valid @RequestBody final SpringSecuritySocialOauthDTO.CreateCustomerRequest createCustomerRequest)
            throws IOException, DataIntegrityViolationException {

        return new GlobalSuccessPayload<>(socialOauthService.createKakaoCustomer(createCustomerRequest));

    }


    /* 2. 네이버 */

    @PostMapping("/social-oauth/token/naver")
    public GlobalSuccessPayload<SpringSecuritySocialOauthDTO.TokenResponse> createAccessTokenUsingNaverToken(
            @RequestBody final SpringSecuritySocialOauthDTO.TokenRequest tokenRequest)
            throws IOException {

        return new GlobalSuccessPayload<>(socialOauthService.getAccessTokenUsingNaverToken(tokenRequest));

    }


    @PostMapping("/social-oauth/token/naver/create")
    public GlobalSuccessPayload<SpringSecuritySocialOauthDTO.CreateCustomerResponse> createNaverUser(
            @RequestBody final SpringSecuritySocialOauthDTO.CreateCustomerRequest createCustomerRequest)
            throws IOException, DataIntegrityViolationException  {

        return new GlobalSuccessPayload<>(socialOauthService.createNaverCustomer(createCustomerRequest));

    }

    /* 3. 구글 */

    @PostMapping("/social-oauth/token/google")
    public GlobalSuccessPayload<SpringSecuritySocialOauthDTO.TokenResponse> createAccessTokenUsingGoogleToken(
            @RequestBody final SpringSecuritySocialOauthDTO.TokenRequest tokenRequest)
            throws IOException {

        return new GlobalSuccessPayload<>(socialOauthService.getAccessTokenUsingGoogleToken(tokenRequest));

    }


    @PostMapping("/social-oauth/token/google/create")
    public GlobalSuccessPayload<SpringSecuritySocialOauthDTO.CreateCustomerResponse> createGoogleUser(
            @RequestBody final SpringSecuritySocialOauthDTO.CreateCustomerRequest createCustomerRequest)
            throws IOException, DataIntegrityViolationException  {

        return new GlobalSuccessPayload<>(socialOauthService.createGoogleCustomer(createCustomerRequest));

    }


    /* 4. 애플 : 인 웹으로 구현 web 폴더 참조 */
    @PostMapping("/social-oauth/token/apple/create")
    public GlobalSuccessPayload<SpringSecuritySocialOauthDTO.CreateCustomerResponse> createAppleUser(
            @RequestBody final SpringSecuritySocialOauthDTO.CreateAppleCustomerRequest createAppleCustomerRequest)
            throws IOException, DataIntegrityViolationException  {

        return new GlobalSuccessPayload<>(socialOauthService.createAppleCustomer(createAppleCustomerRequest));

    }
}
