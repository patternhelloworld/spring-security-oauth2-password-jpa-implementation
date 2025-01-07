package com.patternhelloworld.securityhelper.oauth2.client.config.securityimpl.message;

import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.message.ExceptionMessageInterface;

public enum CustomSecurityUserExceptionMessage implements ExceptionMessageInterface {

    AUTHENTICATION_LOGIN_FAILURE("1Authentication information is not valid. Please check and try again."),
    AUTHENTICATION_LOGIN_ERROR("1An error occurred during authentication. If the problem persists, please contact customer service."),
    AUTHENTICATION_TOKEN_FAILURE("1The authentication token has expired. Please log in again."),
    AUTHENTICATION_TOKEN_ERROR("1There was a problem verifying the authentication token. Please log in again."),
    AUTHORIZATION_FAILURE("1You do not have access permissions. Please request this from the administrator."),
    AUTHORIZATION_ERROR("1An error occurred with access permissions. If the problem persists, please contact customer service."),

    // ID PASSWORD
    AUTHENTICATION_ID_NO_EXISTS("1The specified ID does not exist."),
    AUTHENTICATION_WRONG_ID_PASSWORD("1User information could not be verified. Please check your ID or password. If the problem persists, please contact customer service."),
    AUTHENTICATION_PASSWORD_FAILED_EXCEEDED("1The number of password attempts has been exceeded."),

    // Wrong Authorization Code
    AUTHENTICATION_INVALID_RESPONSE_TYPE("1The specified Response Type is invalid."),
    AUTHENTICATION_INVALID_AUTHORIZATION_CODE("1The specified Authorization Code is invalid."),
    AUTHENTICATION_EXPIRED_AUTHORIZATION_CODE("1The specified Authorization Code has been expired."),
    AUTHENTICATION_INVALID_REDIRECT_URI("1The specified Redirect URI is invalid."),
    AUTHENTICATION_SCOPES_NOT_APPROVED("1The specified Scopes are not approved."),
    // CLIENT ID, SECRET
    AUTHENTICATION_WRONG_CLIENT_ID_SECRET("1Client information is not verified."),

    // GRANT TYPE
    AUTHENTICATION_WRONG_GRANT_TYPE("1Wrong Grant Type detected.");

    private String message;

    @Override
    public String getMessage() {
        return message;
    }

    CustomSecurityUserExceptionMessage(String message) {
        this.message = message;
    }

}
