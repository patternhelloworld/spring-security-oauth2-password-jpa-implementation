package io.github.patternhelloworld.securityhelper.oauth2.api.config.security.token.generator;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsSet;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import java.util.HashMap;
import java.util.Map;

public class CustomAccessTokenCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

    private final String clientId;
    private final UserDetails userDetails;

    public CustomAccessTokenCustomizer(String clientId, UserDetails userDetails) {
        this.clientId = clientId;
        this.userDetails = userDetails;
    }

    @Override
    public void customize(JwtEncodingContext context) {
        if (context == null) {
            throw new IllegalArgumentException("JwtEncodingContext cannot be null");
        }
        context.getClaims().claim("client_id", clientId);
        context.getClaims().claim("username", this.userDetails.getUsername());
    }

}
