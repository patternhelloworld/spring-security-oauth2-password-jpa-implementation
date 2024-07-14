package com.patternknife.securityhelper.oauth2.api.config.response.error.dto;

import java.util.Map;

public interface ISecurityMessages {
    // Logged but NOT sent to clients
    String getMessage();
    // Logged and sent to clients
    String getUserMessage();
    // Logged and sent to clients in the format of an array of "field":"message" pairs.
    Map<String, String> getUserValidationMessage();
}
