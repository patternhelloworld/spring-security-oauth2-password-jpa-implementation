package com.patternknife.securityhelper.oauth2.config.logger.dto;

import lombok.Builder;
import lombok.ToString;

import java.util.Map;

@ToString
@Builder
public class ErrorMessages {

	// Never to be returned to clients, but must be logged.
	// @JsonIgnore
	private String message;
	private String userMessage;
	private Map<String, String> userValidationMessage;

	public String getMessage() {
		return message;
	}

	public String getUserMessage() {
		return userMessage;
	}

	public Map<String, String> getUserValidationMessage() {
		return userValidationMessage;
	}
}
