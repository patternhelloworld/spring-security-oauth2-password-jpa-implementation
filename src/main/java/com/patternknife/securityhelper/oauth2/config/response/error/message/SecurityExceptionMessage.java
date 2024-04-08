package com.patternknife.securityhelper.oauth2.config.response.error.message;


public enum SecurityExceptionMessage implements ExceptionMessageInterface {

    // GENERAL (Failure : errors that customers need to recognize / Error : system errors that customers shouldn't understand.)
    AUTHENTICATION_FAILURE("Authentication has been released. Please log in again."),
    AUTHENTICATION_ERROR("An error occurred in authentication. If the problem persists, please contact customer service."),
    AUTHORIZATION_FAILURE("You do not have access permission. Please request access from the administrator."),
    AUTHORIZATION_ERROR("An error occurred in access permissions. If the problem persists, please contact customer service."),

    // OTP
    OTP_NOT_FOUND("OTP value is not verified."),
    OTP_MISMATCH("The current OTP value has expired, and the OTP value you entered does not match the server OTP value. Please re-enter."),

    // ID PASSWORD
    ID_NO_EXISTS("The ID does not exist."),
    WRONG_ID_PASSWORD("User information is not verified. Please check your ID or password. If the problem continues, please contact customer service."),
    PASSWORD_FAILED_EXCEEDED("Password failure attempts have been exceeded."),

    // CLIENT ID, SECRET
    CLIENT_NO_EXISTS("The Client ID does not exist."),
    WRONG_CLIENT_ID_SECRET("Client information is not verified."),

    // GRANT TYPE
    WRONG_GRANT_TYPE("Wrong Grant Type"),

    // SOCIAL
    SOCIAL_NO_RESPONSE("No response was received from social media. If the problem persists, please contact the administrator."),
    SOCIAL_ID_NAME_NOT_AUTHENTICATED("Social account information cannot be found.");


    private String message;

    @Override
    public String getMessage() {
        return message;
    }

    SecurityExceptionMessage(String message) {
        this.message = message;
    }

}
