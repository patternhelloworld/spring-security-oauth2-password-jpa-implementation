package com.patternknife.securityhelper.oauth2.domain.admin.exception;

import com.patternknife.securityhelper.oauth2.config.logger.dto.ErrorMessages;
import com.patternknife.securityhelper.oauth2.config.response.error.exception.auth.UnauthenticatedException;
import com.patternknife.securityhelper.oauth2.config.response.error.message.SecurityExceptionMessage;

public class PasswordFailedExceededException extends UnauthenticatedException {
    public PasswordFailedExceededException() {
        super(SecurityExceptionMessage.PASSWORD_FAILED_EXCEEDED.getMessage());
    }

    public PasswordFailedExceededException(String message) {
        super(message);
    }

    public PasswordFailedExceededException(String message, Throwable cause) {
        super(message, cause);
    }

    public PasswordFailedExceededException(ErrorMessages errorMessages) {
        super(errorMessages);
    }
}
