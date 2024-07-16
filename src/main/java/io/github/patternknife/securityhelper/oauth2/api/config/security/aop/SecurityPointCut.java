package io.github.patternknife.securityhelper.oauth2.api.config.security.aop;

import io.github.patternknife.securityhelper.oauth2.api.config.security.entity.CustomOauthAccessToken;
import io.github.patternknife.securityhelper.oauth2.api.config.security.entity.CustomOauthRefreshToken;
import io.github.patternknife.securityhelper.oauth2.api.config.security.entity.OauthClientDetail;
import jakarta.annotation.Nullable;

public interface SecurityPointCut {
    <T> @Nullable T afterTokensSaved(@Nullable CustomOauthAccessToken customOauthAccessToken, @Nullable CustomOauthRefreshToken customOauthRefreshToken, @Nullable OauthClientDetail oauthClientDetail);
}
