package io.github.patternhelloworld.securityhelper.oauth2.api.config.security.validator.endpoint.authorization;

import lombok.Builder;
import lombok.Data;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.util.Set;

@Data
@Builder
public class CodeValidationResult {
    private String clientId;
    private String responseType;
    private String redirectUri;
    private String state;
    private Set<String> scope;
    private RegisteredClient registeredClient;
}