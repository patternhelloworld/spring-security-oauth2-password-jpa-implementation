package com.github.patternknife.securityhelper.oauth2.api.config.security.response.error.exception;



import com.github.patternknife.securityhelper.oauth2.api.config.security.response.error.dto.ErrorMessages;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;

/*
*   Only OAuth2AuthenticationException is allowed to be tossed.
* */
public class KnifeOauth2AuthenticationException extends OAuth2AuthenticationException {
    protected ErrorMessages errorMessages;

    public KnifeOauth2AuthenticationException(){
        super("default");
    }
    public KnifeOauth2AuthenticationException(String message){
        super(message);
        errorMessages = ErrorMessages.builder().userMessage(message).message(message).build();
    }

    public KnifeOauth2AuthenticationException(ErrorMessages errorMessages){
        super(errorMessages.getMessage() == null ? "default" : errorMessages.getMessage());
        this.errorMessages = errorMessages;
    }
    public ErrorMessages getErrorMessages() {
        return errorMessages;
    }

}