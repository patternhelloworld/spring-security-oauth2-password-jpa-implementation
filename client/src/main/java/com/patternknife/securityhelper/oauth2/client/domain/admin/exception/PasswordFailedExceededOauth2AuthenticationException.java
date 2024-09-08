package com.patternknife.securityhelper.oauth2.client.domain.admin.exception;

import com.github.patternknife.securityhelper.oauth2.api.config.security.response.error.dto.ErrorMessages;
import com.github.patternknife.securityhelper.oauth2.api.config.security.response.error.exception.KnifeOauth2AuthenticationException;
import com.github.patternknife.securityhelper.oauth2.api.config.security.message.DefaultSecurityUserExceptionMessage;

public class PasswordFailedExceededOauth2AuthenticationException extends KnifeOauth2AuthenticationException {
    public PasswordFailedExceededOauth2AuthenticationException() {
        super(DefaultSecurityUserExceptionMessage.AUTHENTICATION_PASSWORD_FAILED_EXCEEDED.getMessage());
    }

    public PasswordFailedExceededOauth2AuthenticationException(String message) {
        super(message);
    }

    public PasswordFailedExceededOauth2AuthenticationException(ErrorMessages errorMessages) {
        super(errorMessages);
    }
}
