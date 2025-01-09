package io.github.patternhelloworld.securityhelper.oauth2.api.config.security.response.error.exception;



import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.response.error.dto.EasyPlusErrorMessages;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;

/*
*   Only OAuth2AuthenticationException is allowed to be tossed according to "spring-authorization-server".
* */
public class EasyPlusOauth2AuthenticationException extends OAuth2AuthenticationException {
    protected EasyPlusErrorMessages easyPlusErrorMessages;

    public EasyPlusOauth2AuthenticationException(){
        super("default");
    }
    public EasyPlusOauth2AuthenticationException(String message){
        super(message);
        easyPlusErrorMessages = EasyPlusErrorMessages.builder().userMessage(message).message(message).build();
    }

    public EasyPlusOauth2AuthenticationException(EasyPlusErrorMessages easyPlusErrorMessages){
        super(new OAuth2Error(easyPlusErrorMessages.getErrorCode() == null ? "default" : easyPlusErrorMessages.getErrorCode()), easyPlusErrorMessages.getMessage() == null ? "default" : easyPlusErrorMessages.getMessage());
        this.easyPlusErrorMessages = easyPlusErrorMessages;
    }

    public EasyPlusOauth2AuthenticationException(EasyPlusErrorMessages easyPlusErrorMessages, Throwable cause) {
        super(new OAuth2Error(easyPlusErrorMessages.getErrorCode() == null ? "default" : easyPlusErrorMessages.getErrorCode()),
                easyPlusErrorMessages.getMessage() == null ? "default" : easyPlusErrorMessages.getMessage(), cause);
        this.easyPlusErrorMessages = easyPlusErrorMessages;
    }

    public EasyPlusErrorMessages getErrorMessages() {
        return easyPlusErrorMessages;
    }

}