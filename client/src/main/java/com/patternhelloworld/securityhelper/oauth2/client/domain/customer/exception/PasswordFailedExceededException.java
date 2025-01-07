package com.patternhelloworld.securityhelper.oauth2.client.domain.customer.exception;

import com.patternhelloworld.securityhelper.oauth2.client.config.response.error.message.GeneralErrorMessage;
import lombok.Getter;

@Getter
public class PasswordFailedExceededException extends RuntimeException {

    private GeneralErrorMessage generalErrorMessage;

    public PasswordFailedExceededException() {
        this.generalErrorMessage = GeneralErrorMessage.PASSWORD_FAILED_EXCEEDED;
    }
}
