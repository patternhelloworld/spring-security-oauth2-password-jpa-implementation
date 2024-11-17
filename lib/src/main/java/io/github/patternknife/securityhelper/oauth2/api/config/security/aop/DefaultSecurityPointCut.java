package io.github.patternknife.securityhelper.oauth2.api.config.security.aop;

import io.github.patternknife.securityhelper.oauth2.api.config.security.entity.KnifeAuthorization;
import io.github.patternknife.securityhelper.oauth2.api.config.security.entity.KnifeClient;
import jakarta.annotation.Nullable;

public class DefaultSecurityPointCut implements SecurityPointCut {
    @Override
    public <T> @Nullable T afterTokensSaved(@Nullable KnifeAuthorization knifeAuthorization, @Nullable KnifeClient knifeClient) {
        return null;
    }
}
