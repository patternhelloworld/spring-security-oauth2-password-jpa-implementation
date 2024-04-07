package com.patternknife.securityhelper.oauth2.domain.socialoauth.service.apple;

import com.patternknife.securityhelper.oauth2.domain.socialoauth.dto.apple.AppleUserInfo;
import com.patternknife.securityhelper.oauth2.domain.socialoauth.dto.apple.TokenResponse;
import com.patternknife.securityhelper.oauth2.domain.socialoauth.utils.apple.AppleUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class AppleServiceImpl implements AppleService {

    @Autowired
    AppleUtils appleUtils;

    /**
     * code 또는 refresh_token가 유효한지 Apple Server에 검증 요청
     *
     * @param client_secret
     * @param code
     * @param refresh_token
     * @return
     */
    @Override
    public TokenResponse requestCodeValidations(String client_secret, String code, String refresh_token) {

        TokenResponse tokenResponse = new TokenResponse();

        if (client_secret != null && code != null && refresh_token == null) {
            tokenResponse = appleUtils.validateAuthorizationGrantCode(client_secret, code);
        } else if (client_secret != null && code == null && refresh_token != null) {
            tokenResponse = appleUtils.validateAnExistingRefreshToken(client_secret, refresh_token);
        }

        return tokenResponse;
    }

    /**
     * Apple login page 호출을 위한 Meta 정보 가져오기
     *
     * @return
     */
    @Override
    public Map<String, String> getLoginMetaInfo() {
        return appleUtils.getMetaInfo();
    }

    /**
     * id_token에서 payload 데이터 가져오기
     *
     * @return
     */
    @Override
    public AppleUserInfo getAppleUserInfo(String id_token) {
        return appleUtils.decodeFromIdToken(id_token);
    }
}
