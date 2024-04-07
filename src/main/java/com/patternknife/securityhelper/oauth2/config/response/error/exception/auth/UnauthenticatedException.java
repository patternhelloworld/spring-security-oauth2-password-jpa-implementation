package com.patternknife.securityhelper.oauth2.config.response.error.exception.auth;

import com.patternknife.securityhelper.oauth2.config.logger.dto.ErrorMessages;
import com.patternknife.securityhelper.oauth2.config.response.error.exception.ErrorMessagesContainedExceptionForSecurityAuthentication;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

// authenticated : 401
// authorized : 403
@ResponseStatus(value = HttpStatus.UNAUTHORIZED)
public class UnauthenticatedException extends ErrorMessagesContainedExceptionForSecurityAuthentication {
    public UnauthenticatedException() {
    }

    public UnauthenticatedException(String message) {
        super(message);
    }

    public UnauthenticatedException(String message, Throwable cause) {
        super(message, cause);
    }

    public UnauthenticatedException(ErrorMessages errorMessages) {
        super(errorMessages);
    }

}