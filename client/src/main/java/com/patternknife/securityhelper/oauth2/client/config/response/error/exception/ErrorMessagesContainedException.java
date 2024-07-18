package com.patternknife.securityhelper.oauth2.client.config.response.error.exception;

import io.github.patternknife.securityhelper.oauth2.api.config.security.response.error.dto.ErrorMessages;

public abstract class ErrorMessagesContainedException extends RuntimeException {

	protected ErrorMessages errorMessages;

	public ErrorMessagesContainedException(){

	}
	public ErrorMessagesContainedException(String message){
		super(message);
	}
	public ErrorMessagesContainedException(String message, Throwable cause) {
		super(message, cause);
	}
	public ErrorMessagesContainedException(ErrorMessages errorMessages){
		this.errorMessages = errorMessages;
	}
	public ErrorMessages getErrorMessages() {
		return errorMessages;
	}
}
