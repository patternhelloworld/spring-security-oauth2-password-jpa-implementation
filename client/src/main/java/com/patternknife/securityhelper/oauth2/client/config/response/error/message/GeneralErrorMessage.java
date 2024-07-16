package com.patternknife.securityhelper.oauth2.client.config.response.error.message;

import com.patternknife.securityhelper.oauth2.api.config.security.message.ExceptionMessageInterface;
import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public enum GeneralErrorMessage implements ExceptionMessageInterface {

    UNHANDLED_ERROR("G_000", "An unhandled error has occurred.", "We apologize for the inconvenience. If the problem persists upon retry, please contact the administrator. Log checking is required.", HttpStatus.INTERNAL_SERVER_ERROR),

    NULL_VALUE_FOUND("G_001", "A null value was detected.", "We apologize for the inconvenience. If the problem persists upon retry, please contact the administrator. Log checking is required.", HttpStatus.BAD_REQUEST),
    DUPLICATE_VALUE_FOUND("G_002", "A duplicate value was detected.", "A duplicate value was detected.", HttpStatus.CONFLICT),
    INPUT_VALUE_INVALID("G_003", "The input value is invalid.", "The input value is invalid.", HttpStatus.BAD_REQUEST),

    ACCOUNT_NOT_FOUND("S_000", "The member could not be found.", "The member could not be found.", HttpStatus.NOT_FOUND),
    EMAIL_DUPLICATION("S_001", "The email is duplicated.", "The email is duplicated.", HttpStatus.CONFLICT),
    PASSWORD_FAILED_EXCEEDED("S_002", "Password failure attempts have been exceeded.", "Password failure attempts have been exceeded.", HttpStatus.BAD_REQUEST);


    private final String code;
    private final String message;
    private final String userMessage;
    private final HttpStatus status;

    GeneralErrorMessage(String code, String message, String userMessage, HttpStatus status) {
        this.code = code;
        this.message = message;
        this.userMessage = userMessage;
        this.status = status;
    }

}
