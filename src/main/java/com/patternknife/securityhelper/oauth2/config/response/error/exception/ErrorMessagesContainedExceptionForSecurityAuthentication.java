package com.patternknife.securityhelper.oauth2.config.response.error.exception;

import com.patternknife.securityhelper.oauth2.config.logger.dto.ErrorMessages;
import org.springframework.security.core.AuthenticationException;

public abstract class ErrorMessagesContainedExceptionForSecurityAuthentication extends AuthenticationException {

	protected ErrorMessages errorMessages;

	public ErrorMessagesContainedExceptionForSecurityAuthentication(){
		super(null);
	}
	public ErrorMessagesContainedExceptionForSecurityAuthentication(String message){
		super(message);
	}
	public ErrorMessagesContainedExceptionForSecurityAuthentication(String message, Throwable cause) {
		super(message, cause);
	}
	public ErrorMessagesContainedExceptionForSecurityAuthentication(ErrorMessages errorMessages){
		super(null);
		this.errorMessages = errorMessages;
	}
	public ErrorMessages getErrorMessages() {
		return errorMessages;
	}
}
