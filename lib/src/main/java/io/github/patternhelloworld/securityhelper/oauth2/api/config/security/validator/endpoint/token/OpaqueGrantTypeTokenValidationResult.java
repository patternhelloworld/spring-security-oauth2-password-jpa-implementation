package io.github.patternhelloworld.securityhelper.oauth2.api.config.security.validator.endpoint.token;

import jakarta.annotation.Nullable;
import lombok.Builder;
import lombok.Data;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

@Data
@Builder
public class OpaqueGrantTypeTokenValidationResult {
    private String clientId;
    private String grantType;
    @Nullable
    private String code; // grantType : authorization_code
    @Nullable
    private String username; // grantType : password
    @Nullable
    private String password; // grantType : password
    @Nullable
    private String refreshToken; // grantType : refresh_token
    private RegisteredClient registeredClient;
    @Nullable
    private String responseType;
}