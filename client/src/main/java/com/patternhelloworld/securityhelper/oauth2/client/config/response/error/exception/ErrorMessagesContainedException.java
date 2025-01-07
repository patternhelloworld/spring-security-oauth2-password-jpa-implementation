package com.patternhelloworld.securityhelper.oauth2.client.config.response.error.exception;

import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.response.error.dto.EasyPlusErrorMessages;

public abstract class ErrorMessagesContainedException extends RuntimeException {

	protected EasyPlusErrorMessages easyPlusErrorMessages;

	public ErrorMessagesContainedException(){

	}
	public ErrorMessagesContainedException(String message){
		super(message);
	}
	public ErrorMessagesContainedException(String message, Throwable cause) {
		super(message, cause);
	}
	public ErrorMessagesContainedException(EasyPlusErrorMessages easyPlusErrorMessages){
		this.easyPlusErrorMessages = easyPlusErrorMessages;
	}
	public EasyPlusErrorMessages getErrorMessages() {
		return easyPlusErrorMessages;
	}
}
