package com.patternknife.securityhelper.oauth2.config.response.error.exception.auth;

import com.patternknife.securityhelper.oauth2.config.logger.dto.ErrorMessages;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;

public class CustomOauth2AuthenticationException extends OAuth2AuthenticationException {
    protected ErrorMessages errorMessages;

    public CustomOauth2AuthenticationException(){
        super("Default");
    }
    public CustomOauth2AuthenticationException(String message){
        super(message);
        errorMessages = ErrorMessages.builder().userMessage(message).message(message).build();
    }

    public CustomOauth2AuthenticationException(ErrorMessages errorMessages){
        super(errorMessages.getMessage());
        this.errorMessages = errorMessages;
    }
    public ErrorMessages getErrorMessages() {
        return errorMessages;
    }

}