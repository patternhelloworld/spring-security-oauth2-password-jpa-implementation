package com.patternknife.securityhelper.oauth2.client.config.securityimpl.aop;


import com.patternknife.securityhelper.oauth2.api.config.security.aop.SecurityPointCut;
import com.patternknife.securityhelper.oauth2.api.config.security.entity.CustomOauthAccessToken;
import com.patternknife.securityhelper.oauth2.api.config.security.entity.CustomOauthRefreshToken;
import com.patternknife.securityhelper.oauth2.api.config.security.entity.OauthClientDetail;

import jakarta.annotation.Nullable;
import lombok.RequiredArgsConstructor;

import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class SecurityPointCutImpl implements SecurityPointCut {

    @Override
    public <T> @Nullable T afterTokensSaved(@Nullable CustomOauthAccessToken customOauthAccessToken, @Nullable CustomOauthRefreshToken customOauthRefreshToken, @Nullable OauthClientDetail oauthClientDetail) {

        // Implement what you need right after tokens are persisted.
        return null;
    }
}
