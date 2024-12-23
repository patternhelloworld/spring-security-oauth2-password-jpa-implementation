package com.patternknife.securityhelper.oauth2.client.domain.admin.exception;

import io.github.patternknife.securityhelper.oauth2.api.config.security.response.error.dto.KnifeErrorMessages;
import io.github.patternknife.securityhelper.oauth2.api.config.security.response.error.exception.KnifeOauth2AuthenticationException;
import io.github.patternknife.securityhelper.oauth2.api.config.security.message.DefaultSecurityUserExceptionMessage;

public class PasswordFailedExceededOauth2AuthenticationException extends KnifeOauth2AuthenticationException {
    public PasswordFailedExceededOauth2AuthenticationException() {
        super(DefaultSecurityUserExceptionMessage.AUTHENTICATION_PASSWORD_FAILED_EXCEEDED.getMessage());
    }

    public PasswordFailedExceededOauth2AuthenticationException(String message) {
        super(message);
    }

    public PasswordFailedExceededOauth2AuthenticationException(KnifeErrorMessages knifeErrorMessages) {
        super(knifeErrorMessages);
    }
}
