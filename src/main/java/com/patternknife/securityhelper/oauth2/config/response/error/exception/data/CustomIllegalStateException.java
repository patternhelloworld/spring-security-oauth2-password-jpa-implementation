package com.patternknife.securityhelper.oauth2.config.response.error.exception.data;

import com.patternknife.securityhelper.oauth2.config.logger.dto.ErrorMessages;
import com.patternknife.securityhelper.oauth2.config.response.error.exception.ErrorMessagesContainedException;

public class CustomIllegalStateException extends ErrorMessagesContainedException {
    public CustomIllegalStateException() {
    }

    public CustomIllegalStateException(String message) {
        super(message);
    }

    public CustomIllegalStateException(String message, Throwable cause) {
        super(message, cause);
    }

    public CustomIllegalStateException(ErrorMessages errorMessages) {
        super(errorMessages);
    }
}
