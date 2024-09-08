package com.patternknife.securityhelper.oauth2.client.config.securityimpl.aop;


import com.github.patternknife.securityhelper.oauth2.api.config.security.aop.SecurityPointCut;
import com.github.patternknife.securityhelper.oauth2.api.config.security.entity.KnifeOauthAccessToken;
import com.github.patternknife.securityhelper.oauth2.api.config.security.entity.KnifeOauthRefreshToken;
import com.github.patternknife.securityhelper.oauth2.api.config.security.entity.KnifeOauthClientDetail;

import jakarta.annotation.Nullable;
import lombok.RequiredArgsConstructor;

import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class SecurityPointCutImpl implements SecurityPointCut {

    @Override
    public <T> @Nullable T afterTokensSaved(@Nullable KnifeOauthAccessToken knifeOauthAccessToken, @Nullable KnifeOauthRefreshToken knifeOauthRefreshToken, @Nullable KnifeOauthClientDetail knifeOauthClientDetail) {

        // Implement what you need right after tokens are persisted.
        return null;
    }
}
