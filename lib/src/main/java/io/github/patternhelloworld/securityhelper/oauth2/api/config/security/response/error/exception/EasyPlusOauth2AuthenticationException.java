package io.github.patternhelloworld.securityhelper.oauth2.api.config.security.response.error.exception;



import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.response.error.dto.EasyPlusErrorMessages;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;

/*
*   Only OAuth2AuthenticationException is allowed to be tossed.
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
        super(easyPlusErrorMessages.getMessage() == null ? "default" : easyPlusErrorMessages.getMessage());
        this.easyPlusErrorMessages = easyPlusErrorMessages;
    }
    public EasyPlusErrorMessages getErrorMessages() {
        return easyPlusErrorMessages;
    }

}