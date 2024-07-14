package com.patternknife.securityhelper.oauth2.api.config.security.aop;

import com.patternknife.securityhelper.oauth2.api.config.security.entity.CustomOauthAccessToken;
import com.patternknife.securityhelper.oauth2.api.config.security.entity.CustomOauthRefreshToken;
import com.patternknife.securityhelper.oauth2.api.config.security.entity.OauthClientDetail;
import jakarta.annotation.Nullable;

public class DefaultSecurityPointCut implements SecurityPointCut {
    @Override
    public <T> T afterTokensSaved(@Nullable CustomOauthAccessToken customOauthAccessToken, @Nullable CustomOauthRefreshToken customOauthRefreshToken, @Nullable OauthClientDetail oauthClientDetail) {
        return null;
    }
}
