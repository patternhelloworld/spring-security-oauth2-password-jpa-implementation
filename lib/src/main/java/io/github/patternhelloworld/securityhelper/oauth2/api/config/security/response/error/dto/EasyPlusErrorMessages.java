package io.github.patternhelloworld.securityhelper.oauth2.api.config.security.response.error.dto;

import lombok.*;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Map;

@Getter
@Setter
@ToString
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class EasyPlusErrorMessages {

	private String message;
	private String userMessage;
	private Map<String, String> userValidationMessage;
	private UserDetails userDetails;
	private String errorCode;

}
