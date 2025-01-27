package io.github.patternhelloworld.securityhelper.oauth2.api.config.security.response.error.dto;


import com.fasterxml.jackson.annotation.JsonIgnore;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.util.TimestampUtil;
import lombok.ToString;
import org.apache.commons.lang3.StringUtils;

import java.util.Date;
import java.util.Map;

@ToString
public class SecurityEasyPlusErrorResponsePayload {
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


	public SecurityEasyPlusErrorResponsePayload(EasyPlusErrorMessages easyPlusErrorMessages, Exception e, String details, String stackTrace, String userMessage, Map<String, String> userValidationMessage) {
		this.timestamp = TimestampUtil.getPayloadTimestamp();
		this.message = !StringUtils.isEmpty(easyPlusErrorMessages.getMessage()) ? easyPlusErrorMessages.getMessage() : e.getMessage() ;
		this.details = details;
		this.userMessage = !StringUtils.isEmpty(easyPlusErrorMessages.getUserMessage()) ? easyPlusErrorMessages.getUserMessage() : userMessage;
		this.stackTrace = stackTrace;
		this.userValidationMessage = easyPlusErrorMessages.getUserValidationMessage() != null && !easyPlusErrorMessages.getUserValidationMessage().isEmpty() ? easyPlusErrorMessages.getUserValidationMessage() : userValidationMessage;
	}

	public SecurityEasyPlusErrorResponsePayload(String message, String details, String userMessage, String stackTrace) {
		this.timestamp = TimestampUtil.getPayloadTimestamp();
		this.message = message;
		this.details = details;
		this.userMessage = userMessage;
		this.stackTrace = stackTrace;
	}

	public SecurityEasyPlusErrorResponsePayload(String message, String details, String userMessage, String stackTrace, String cause) {
		this.timestamp = TimestampUtil.getPayloadTimestamp();
		this.message = message;
		this.details = details;
		this.userMessage = userMessage;
		this.stackTrace = stackTrace;
		this.cause = cause;
	}

	public SecurityEasyPlusErrorResponsePayload(String message, String details, String userMessage, Map<String, String> userValidationMessage,
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
