package com.github.patternknife.securityhelper.oauth2.api.config.security.aop;

import com.github.patternknife.securityhelper.oauth2.api.config.security.entity.KnifeOauthAccessToken;
import com.github.patternknife.securityhelper.oauth2.api.config.security.entity.KnifeOauthClientDetail;
import com.github.patternknife.securityhelper.oauth2.api.config.security.entity.KnifeOauthRefreshToken;
import jakarta.annotation.Nullable;

public interface SecurityPointCut {
    <T> @Nullable T afterTokensSaved(@Nullable KnifeOauthAccessToken knifeOauthAccessToken, @Nullable KnifeOauthRefreshToken knifeOauthRefreshToken, @Nullable KnifeOauthClientDetail knifeOauthClientDetail);
}
