package com.patternknife.securityhelper.oauth2.domain.socialoauth.service.apple;

import com.patternknife.securityhelper.oauth2.domain.socialoauth.dto.apple.AppleUserInfo;
import com.patternknife.securityhelper.oauth2.domain.socialoauth.dto.apple.TokenResponse;

import java.util.Map;

public interface AppleService {

    TokenResponse requestCodeValidations(String client_secret, String code, String refresh_token);

    Map<String, String> getLoginMetaInfo();

    AppleUserInfo getAppleUserInfo(String id_token);

}
