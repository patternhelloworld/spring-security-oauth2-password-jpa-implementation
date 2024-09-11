package com.patternknife.securityhelper.oauth2.client.config.securityimpl.aop;


import io.github.patternknife.securityhelper.oauth2.api.config.security.aop.SecurityPointCut;

import io.github.patternknife.securityhelper.oauth2.api.config.security.entity.KnifeAuthorization;
import io.github.patternknife.securityhelper.oauth2.api.config.security.entity.KnifeClient;
import jakarta.annotation.Nullable;
import lombok.RequiredArgsConstructor;

import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class SecurityPointCutImpl implements SecurityPointCut {
    @Override
    public <T> @Nullable T afterTokensSaved(@Nullable KnifeAuthorization knifeAuthorization, @Nullable KnifeClient knifeClient) {
        // Implement what you need right after tokens are persisted.
        return null;
    }
}
