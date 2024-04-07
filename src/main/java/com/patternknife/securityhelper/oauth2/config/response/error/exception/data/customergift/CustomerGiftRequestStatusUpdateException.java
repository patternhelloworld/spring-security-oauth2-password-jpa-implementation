package com.patternknife.securityhelper.oauth2.config.response.error.exception.data.customergift;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(value = HttpStatus.CONFLICT)
public class CustomerGiftRequestStatusUpdateException extends RuntimeException{
	public CustomerGiftRequestStatusUpdateException(String message){
		super(message);
	}
	public CustomerGiftRequestStatusUpdateException(String message, Throwable cause) {
		super(message, cause);
	}
}
