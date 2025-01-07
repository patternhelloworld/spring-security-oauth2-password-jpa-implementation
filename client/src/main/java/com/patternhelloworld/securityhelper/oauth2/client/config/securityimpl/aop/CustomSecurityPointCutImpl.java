package com.patternhelloworld.securityhelper.oauth2.client.config.securityimpl.aop;

import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.aop.SecurityPointCut;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.entity.EasyPlusAuthorization;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.entity.EasyPlusClient;
import jakarta.annotation.Nullable;
import lombok.RequiredArgsConstructor;

import org.springframework.stereotype.Service;

/*
 *
 * The functionality is already implemented in the library's
 * 'aop.security.config.io.github.patternhelloworld.securityhelper.oauth2.api.DefaultSecurityPointCut'.
 *
 * Create this class only if you need a custom implementation that differs from the default.
 */
@Service
@RequiredArgsConstructor
public class CustomSecurityPointCutImpl implements SecurityPointCut {
    @Override
    public <T> @Nullable T afterTokensSaved(@Nullable EasyPlusAuthorization easyPlusAuthorization, @Nullable EasyPlusClient easyPlusClient) {
        // Implement what you need right after tokens are persisted.
        return null;
    }
}
