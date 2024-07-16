package com.patternknife.securityhelper.oauth2.client.domain.admin.exception;

import com.patternknife.securityhelper.oauth2.api.config.response.error.dto.ErrorMessages;
import com.patternknife.securityhelper.oauth2.api.config.response.error.exception.auth.KnifeOauth2AuthenticationException;
import com.patternknife.securityhelper.oauth2.api.config.response.error.message.SecurityUserExceptionMessage;

public class PasswordFailedExceededOauth2AuthenticationException extends KnifeOauth2AuthenticationException {
    public PasswordFailedExceededOauth2AuthenticationException() {
        super(SecurityUserExceptionMessage.AUTHENTICATION_PASSWORD_FAILED_EXCEEDED.getMessage());
    }

    public PasswordFailedExceededOauth2AuthenticationException(String message) {
        super(message);
    }

    public PasswordFailedExceededOauth2AuthenticationException(ErrorMessages errorMessages) {
        super(errorMessages);
    }
}
