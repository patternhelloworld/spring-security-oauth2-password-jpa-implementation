package com.patternknife.securityhelper.oauth2.client.config.response.error.dto;


import com.fasterxml.jackson.annotation.JsonIgnore;
import com.github.patternknife.securityhelper.oauth2.api.config.util.TimestampUtil;
import com.github.patternknife.securityhelper.oauth2.api.config.security.response.error.dto.ErrorMessages;

import lombok.ToString;
import org.apache.commons.lang3.StringUtils;

import java.util.Date;
import java.util.Map;

@ToString
public class CustomErrorResponsePayload {
	private Date timestamp;

	// Never to be returned to clients, but must be logged.
	//@JsonIgnore
	private String message;
	private String details;
	private String userMessage;
	private Map<String, String> userValidationMessage;

	@JsonIgnore
	private String stackTrace;
	@JsonIgnore
	private String cause;


	public CustomErrorResponsePayload(ErrorMessages errorMessages, Exception e, String details, String stackTrace, String userMessage, Map<String, String> userValidationMessage) {
		this.timestamp = TimestampUtil.getPayloadTimestamp();
		this.message = !StringUtils.isEmpty(errorMessages.getMessage()) ? errorMessages.getMessage() : e.getMessage() ;
		this.details = details;
		this.userMessage = !StringUtils.isEmpty(errorMessages.getUserMessage()) ? errorMessages.getUserMessage() : userMessage;
		this.stackTrace = stackTrace;
		this.userValidationMessage = errorMessages.getUserValidationMessage() != null && !errorMessages.getUserValidationMessage().isEmpty() ? errorMessages.getUserValidationMessage() : userValidationMessage;
	}

	public CustomErrorResponsePayload(String message, String details, String userMessage, String stackTrace) {
		this.timestamp = TimestampUtil.getPayloadTimestamp();
		this.message = message;
		this.details = details;
		this.userMessage = userMessage;
		this.stackTrace = stackTrace;
	}

	public CustomErrorResponsePayload(String message, String details, String userMessage, String stackTrace, String cause) {
		this.timestamp = TimestampUtil.getPayloadTimestamp();
		this.message = message;
		this.details = details;
		this.userMessage = userMessage;
		this.stackTrace = stackTrace;
		this.cause = cause;
	}

	public CustomErrorResponsePayload(String message, String details, String userMessage, Map<String, String> userValidationMessage,
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
