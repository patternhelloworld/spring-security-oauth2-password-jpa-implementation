package com.patternknife.securityhelper.oauth2.domain.admin.exception;

import com.patternknife.securityhelper.oauth2.config.logger.dto.ErrorMessages;
import com.patternknife.securityhelper.oauth2.config.response.error.exception.auth.CustomOauth2AuthenticationException;
import com.patternknife.securityhelper.oauth2.config.response.error.message.SecurityUserExceptionMessage;

public class PasswordFailedExceededExceptionCustomOauth2 extends CustomOauth2AuthenticationException {
    public PasswordFailedExceededExceptionCustomOauth2() {
        super(SecurityUserExceptionMessage.PASSWORD_FAILED_EXCEEDED.getMessage());
    }

    public PasswordFailedExceededExceptionCustomOauth2(String message) {
        super(message);
    }

    public PasswordFailedExceededExceptionCustomOauth2(ErrorMessages errorMessages) {
        super(errorMessages);
    }
}
