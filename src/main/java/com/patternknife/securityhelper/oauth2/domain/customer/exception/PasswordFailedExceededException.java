package com.patternknife.securityhelper.oauth2.domain.customer.exception;

import com.patternknife.securityhelper.oauth2.config.response.error.message.GeneralErrorMessage;
import lombok.Getter;

@Getter
public class PasswordFailedExceededException extends RuntimeException {

    private GeneralErrorMessage generalErrorMessage;

    public PasswordFailedExceededException() {
        this.generalErrorMessage = GeneralErrorMessage.PASSWORD_FAILED_EXCEEDED;
    }
}
