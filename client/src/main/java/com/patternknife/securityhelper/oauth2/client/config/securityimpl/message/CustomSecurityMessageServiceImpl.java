package com.patternknife.securityhelper.oauth2.client.config.securityimpl.message;


import io.github.patternknife.securityhelper.oauth2.api.config.security.message.DefaultSecurityUserExceptionMessage;
import io.github.patternknife.securityhelper.oauth2.api.config.security.message.ISecurityUserExceptionMessageService;
import org.springframework.context.annotation.Configuration;

/*
 *
 * The functionality is already implemented in the library's
 * 'io.github.patternknife.securityhelper.oauth2.api.config.security.message.DefaultSecurityMessageServiceImpl'.
 *
 * Create this class only if you need a custom implementation that differs from the default.
 */
@Configuration
public class CustomSecurityMessageServiceImpl implements ISecurityUserExceptionMessageService {

    @Override
    public String getUserMessage(DefaultSecurityUserExceptionMessage defaultSecurityUserExceptionMessage) {
        try {
            CustomSecurityUserExceptionMessage customMessage = CustomSecurityUserExceptionMessage.valueOf(defaultSecurityUserExceptionMessage.name());
            return customMessage.getMessage();
        } catch (IllegalArgumentException e) {
            return defaultSecurityUserExceptionMessage.getMessage();
        }
    }

}
