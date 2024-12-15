package com.patternknife.securityhelper.oauth2.client.config.response.error.exception;

import io.github.patternknife.securityhelper.oauth2.api.config.security.response.error.dto.KnifeErrorMessages;

public abstract class ErrorMessagesContainedException extends RuntimeException {

	protected KnifeErrorMessages knifeErrorMessages;

	public ErrorMessagesContainedException(){

	}
	public ErrorMessagesContainedException(String message){
		super(message);
	}
	public ErrorMessagesContainedException(String message, Throwable cause) {
		super(message, cause);
	}
	public ErrorMessagesContainedException(KnifeErrorMessages knifeErrorMessages){
		this.knifeErrorMessages = knifeErrorMessages;
	}
	public KnifeErrorMessages getErrorMessages() {
		return knifeErrorMessages;
	}
}
