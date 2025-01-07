package io.github.patternhelloworld.securityhelper.oauth2.api.config.security.aop;

import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.entity.EasyPlusAuthorization;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.entity.EasyPlusClient;
import jakarta.annotation.Nullable;

public class DefaultSecurityPointCut implements SecurityPointCut {
    @Override
    public <T> @Nullable T afterTokensSaved(@Nullable EasyPlusAuthorization easyPlusAuthorization, @Nullable EasyPlusClient easyPlusClient) {
        return null;
    }
}
