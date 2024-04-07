package com.patternknife.securityhelper.oauth2.domain.socialoauth.web;


import com.patternknife.securityhelper.oauth2.config.logger.module.ResponseErrorLogConfig;
import com.patternknife.securityhelper.oauth2.domain.socialoauth.dto.SpringSecuritySocialOauthDTO;
import com.patternknife.securityhelper.oauth2.domain.socialoauth.dto.apple.ServicesResponse;
import com.patternknife.securityhelper.oauth2.domain.socialoauth.dto.apple.AppsResponse;
import com.patternknife.securityhelper.oauth2.domain.socialoauth.dto.apple.AppleUserInfo;
import com.patternknife.securityhelper.oauth2.domain.socialoauth.dto.apple.TokenResponse;
import com.patternknife.securityhelper.oauth2.domain.socialoauth.service.SocialOauthService;
import com.patternknife.securityhelper.oauth2.domain.socialoauth.service.apple.AppleService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.util.Map;

// https://whitepaek.tistory.com/60
@Controller
public class SocialOauthWeb {

    private Logger logger = LoggerFactory.getLogger(ResponseErrorLogConfig.class);

    @Autowired
    AppleService appleService;

    @Autowired
    SocialOauthService socialOauthService;



    /**
     * Apple login page Controller (SSL - https)
     * @return
     */
    @GetMapping(value = "/social-oauth/apple/login")
    public String appleLogin() {
        Map<String, String> metaInfo = appleService.getLoginMetaInfo();

        String url = UriComponentsBuilder.fromUriString("https://appleid.apple.com/auth/authorize")
                .queryParam("client_id", metaInfo.get("CLIENT_ID"))
                .queryParam("redirect_uri", metaInfo.get("REDIRECT_URI"))
                .queryParam("nonce", metaInfo.get("NONCE"))
                .queryParam("response_type", "code id_token")
                .queryParam("scope", "name email")
                .queryParam("response_mode", "form_post")
                .build()
                .toUriString();

        return "redirect:" + url;
    }

    @Value("${app.oauth2.appUser.clientId}")
    private String appUserClientId;

    /**
     * Apple Login 유저 정보를 받은 후 권한 생성
     *
     * @param serviceResponse
     * @return
     */
    @PostMapping(value = "/social-oauth/apple/callback")
    public String servicesRedirect(ServicesResponse serviceResponse, @RequestHeader("host") String host,
                                   @RequestHeader(value = "X-Forwarded-Proto", required = false) String proto) throws IOException {

        String hostName = host.split(":")[0];
        String scheme = proto != null ? proto : "https";

        if (serviceResponse == null) {
            return null;
        }

      //  String code = serviceResponse.getCode();
    //    String client_secret = appleService.getAppleClientSecret(serviceResponse.getId_token());

/*        logger.debug("" +
                "" +
                "" +
                "================================");
        logger.debug("id_token ‣ " + serviceResponse.getId_token());
        logger.debug("payload ‣ " + appleService.getPayload(serviceResponse.getId_token()));
        logger.debug("client_secret ‣ " + client_secret);
        logger.debug("================================");*/

        // return appleService.requestCodeValidations(client_secret, code, null);

        AppleUserInfo payload = appleService.getAppleUserInfo(serviceResponse.getId_token());


        return socialOauthService.redirectWithTokenResponseUsingAppleToken(new SpringSecuritySocialOauthDTO.NonDependentTokenRequest(appUserClientId), payload, hostName, scheme, serviceResponse.getId_token());

    }

    /**
     * refresh_token 유효성 검사
     *
     * @param client_secret
     * @param refresh_token
     * @return
     */
    @PostMapping(value = "/refresh")
    @ResponseBody
    public TokenResponse refreshRedirect(@RequestParam String client_secret, @RequestParam String refresh_token) {
        return appleService.requestCodeValidations(client_secret, null, refresh_token);
    }

    /**
     * Apple 유저의 이메일 변경, 서비스 해지, 계정 탈퇴에 대한 Notifications을 받는 Controller (SSL - https (default: 443))
     *
     * @param appsResponse
     */
    @PostMapping(value = "/apps/to/endpoint")
    @ResponseBody
    public void appsToEndpoint(@RequestBody AppsResponse appsResponse) {
        logger.debug("[/path/to/endpoint] RequestBody ‣ " + appsResponse.getPayload());
    }

}
