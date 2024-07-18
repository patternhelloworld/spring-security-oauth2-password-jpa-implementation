package io.github.patternknife.securityhelper.oauth2.api.config.security.aop;

import io.github.patternknife.securityhelper.oauth2.api.config.security.entity.KnifeOauthAccessToken;
import io.github.patternknife.securityhelper.oauth2.api.config.security.entity.KnifeOauthRefreshToken;
import io.github.patternknife.securityhelper.oauth2.api.config.security.entity.KnifeOauthClientDetail;
import jakarta.annotation.Nullable;

public class DefaultSecurityPointCut implements SecurityPointCut {
    @Override
    public <T> T afterTokensSaved(@Nullable KnifeOauthAccessToken knifeOauthAccessToken, @Nullable KnifeOauthRefreshToken knifeOauthRefreshToken, @Nullable KnifeOauthClientDetail knifeOauthClientDetail) {
        return null;
    }
}
