package io.github.patternknife.securityhelper.oauth2.api.config.response.error.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.NoArgsConstructor;
import lombok.ToString;

import java.util.Map;

@ToString
@Builder
@NoArgsConstructor
@AllArgsConstructor
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
