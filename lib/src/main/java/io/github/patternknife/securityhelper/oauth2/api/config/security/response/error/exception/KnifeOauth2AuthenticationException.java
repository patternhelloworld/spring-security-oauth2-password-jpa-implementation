package io.github.patternknife.securityhelper.oauth2.api.config.security.response.error.exception;



import io.github.patternknife.securityhelper.oauth2.api.config.security.response.error.dto.KnifeErrorMessages;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;

/*
*   Only OAuth2AuthenticationException is allowed to be tossed.
* */
public class KnifeOauth2AuthenticationException extends OAuth2AuthenticationException {
    protected KnifeErrorMessages knifeErrorMessages;

    public KnifeOauth2AuthenticationException(){
        super("default");
    }
    public KnifeOauth2AuthenticationException(String message){
        super(message);
        knifeErrorMessages = KnifeErrorMessages.builder().userMessage(message).message(message).build();
    }

    public KnifeOauth2AuthenticationException(KnifeErrorMessages knifeErrorMessages){
        super(knifeErrorMessages.getMessage() == null ? "default" : knifeErrorMessages.getMessage());
        this.knifeErrorMessages = knifeErrorMessages;
    }
    public KnifeErrorMessages getErrorMessages() {
        return knifeErrorMessages;
    }

}