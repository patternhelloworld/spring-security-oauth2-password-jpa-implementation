package com.patternhelloworld.securityhelper.oauth2.client.domain.admin.exception;

import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.response.error.dto.EasyPlusErrorMessages;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.response.error.exception.EasyPlusOauth2AuthenticationException;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.message.DefaultSecurityUserExceptionMessage;

public class PasswordFailedExceededOauth2AuthenticationException extends EasyPlusOauth2AuthenticationException {
    public PasswordFailedExceededOauth2AuthenticationException() {
        super(DefaultSecurityUserExceptionMessage.AUTHENTICATION_PASSWORD_FAILED_EXCEEDED.getMessage());
    }

    public PasswordFailedExceededOauth2AuthenticationException(String message) {
        super(message);
    }

    public PasswordFailedExceededOauth2AuthenticationException(EasyPlusErrorMessages easyPlusErrorMessages) {
        super(easyPlusErrorMessages);
    }
}
