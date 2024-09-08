package io.github.patternknife.securityhelper.oauth2.api.config.security.serivce;

import jakarta.annotation.Nullable;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

public interface IOauth2AuthenticationHashCheckService {
    void validateUsernamePassword(String inputPassword, @Nullable UserDetails userDetails);
    void validateClientCredentials(String inputClientSecret, RegisteredClient registeredClient);
}