package com.patternknife.securityhelper.oauth2.client.domain.admin.exception;

import com.patternknife.securityhelper.oauth2.api.config.response.error.dto.ErrorMessages;
import com.patternknife.securityhelper.oauth2.api.config.response.error.message.SecurityUserExceptionMessage;
import com.patternknife.securityhelper.oauth2.client.config.response.error.exception.auth.CustomOauth2AuthenticationException;

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
