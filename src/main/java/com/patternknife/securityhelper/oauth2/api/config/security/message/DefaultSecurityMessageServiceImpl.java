package com.patternknife.securityhelper.oauth2.api.config.security.message;

public class DefaultSecurityMessageServiceImpl implements ISecurityUserExceptionMessageService {

    @Override
    public String getUserMessage(DefaultSecurityUserExceptionMessage defaultSecurityUserExceptionMessage) {
        return defaultSecurityUserExceptionMessage.getMessage();
    }

}
