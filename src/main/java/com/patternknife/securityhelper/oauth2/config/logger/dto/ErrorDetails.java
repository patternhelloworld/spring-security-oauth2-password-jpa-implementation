package com.patternknife.securityhelper.oauth2.config.logger.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.patternknife.securityhelper.oauth2.config.response.TimestampUtil;
import com.patternknife.securityhelper.oauth2.util.CustomUtils;
import lombok.ToString;

import java.util.Date;
import java.util.Map;

@ToString
public class ErrorDetails {
	private Date timestamp;

	// Never to be returned to clients, but must be logged. See the log file.
	@JsonIgnore
	private String message;
	private String details;
	private String userMessage;
	private Map<String, String> userValidationMessage;

	// Never to be returned to clients, but must be logged. See the log file.
	@JsonIgnore
	private String stackTrace;
	// Never to be returned to clients, but must be logged. See the log file.
	@JsonIgnore
	private String cause;


	public ErrorDetails(ErrorMessages errorMessages, Exception e, String details, String stackTrace, String userMessage, Map<String, String> userValidationMessage) {
		this.timestamp = TimestampUtil.getPayloadTimestamp();
		this.message = !CustomUtils.isEmpty(errorMessages.getMessage()) ? errorMessages.getMessage() : e.getMessage() ;
		this.details = details;
		this.userMessage = !CustomUtils.isEmpty(errorMessages.getUserMessage()) ? errorMessages.getUserMessage() : userMessage;
		this.stackTrace = stackTrace;
		this.userValidationMessage = !CustomUtils.isEmpty(errorMessages.getUserValidationMessage()) ? errorMessages.getUserValidationMessage() : userValidationMessage;
	}

	public ErrorDetails(String message, String details, String userMessage, String stackTrace) {
		this.timestamp = TimestampUtil.getPayloadTimestamp();
		this.message = message;
		this.details = details;
		this.userMessage = userMessage;
		this.stackTrace = stackTrace;
	}

	public ErrorDetails(String message, String details, String userMessage, String stackTrace, String cause) {
		this.timestamp = TimestampUtil.getPayloadTimestamp();
		this.message = message;
		this.details = details;
		this.userMessage = userMessage;
		this.stackTrace = stackTrace;
		this.cause = cause;
	}

	public ErrorDetails(String message, String details, String userMessage, Map<String, String> userValidationMessage,
							String stackTrace, String cause) {

		this.timestamp = TimestampUtil.getPayloadTimestamp();
		this.message = message;
		this.details = details;
		this.userMessage = userMessage;
		this.userValidationMessage = userValidationMessage;
		this.stackTrace = stackTrace;
		this.cause = cause;
	}

	public Date getTimestamp() {
		return timestamp;
	}

	public String getMessage() {
		return message;
	}

	public String getDetails() {
		return details;
	}

	public String getUserMessage() {
		return userMessage;
	}

	public String getStackTrace() {
		return stackTrace;
	}

	public String getCause() {
		return cause;
	}

	public Map<String, String> getUserValidationMessage() {
		return userValidationMessage;
	}
}
