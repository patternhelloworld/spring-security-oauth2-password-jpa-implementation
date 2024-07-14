package com.patternknife.securityhelper.oauth2.client.config.response.error.exception.data;

import com.patternknife.securityhelper.oauth2.api.config.response.error.dto.ErrorMessages;
import com.patternknife.securityhelper.oauth2.client.config.response.error.exception.ErrorMessagesContainedException;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(value = HttpStatus.NOT_FOUND)
public class ResourceNotFoundException extends ErrorMessagesContainedException {
	public ResourceNotFoundException() {
	}

	public ResourceNotFoundException(String message) {
		super(message);
	}

	public ResourceNotFoundException(String message, Throwable cause) {
		super(message, cause);
	}

	public ResourceNotFoundException(ErrorMessages errorMessages) {
		super(errorMessages);
	}
}
