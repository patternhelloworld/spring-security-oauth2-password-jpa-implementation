package io.github.patternknife.securityhelper.oauth2.api.config.security.entity;

import io.github.patternknife.securityhelper.oauth2.api.config.security.token.generator.CustomAuthenticationKeyGenerator;
import io.github.patternknife.securityhelper.oauth2.api.config.security.util.SerializableObjectConverter;
import jakarta.persistence.*;

import lombok.Data;
import org.hibernate.annotations.DynamicUpdate;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;

import java.time.Instant;
import java.time.LocalDateTime;

@Table(name="oauth2_authorization")
@Entity
@Data
@DynamicUpdate
public class KnifeAuthorization {

    // From Oauth2Authorization, oAuth2Authorization.getId() (refer to 'Spring-Authorization-Server')
    @Id
    @Column(name = "id")
    private String id;

    @Column(name = "registered_client_id", length = 100, nullable = false)
    private String registeredClientId;

    @Column(name = "principal_name", length = 200, nullable = false)
    private String principalName;

    @Column(name = "authorization_grant_type", length = 100, nullable = false)
    private String authorizationGrantType;

    @Column(name = "authorized_scopes", length = 1000)
    private String authorizedScopes;

    @Lob
    @Column(name = "attributes")
    private String attributes;

    @Column(name = "state", length = 500)
    private String state;

    @Lob
    @Column(name = "authorization_code_value")
    private String authorizationCodeValue;

    @Column(name = "authorization_code_issued_at")
    private LocalDateTime authorizationCodeIssuedAt;

    @Column(name = "authorization_code_expires_at")
    private LocalDateTime authorizationCodeExpiresAt;

    @Lob
    @Column(name = "authorization_code_metadata")
    private String authorizationCodeMetadata;

    @Column(name = "access_token_value", length = 1000)
    private String accessTokenValue;

    @Column(name = "access_token_issued_at")
    private LocalDateTime accessTokenIssuedAt;

    @Column(name = "access_token_expires_at")
    private LocalDateTime accessTokenExpiresAt;

    @Lob
    @Column(name = "access_token_metadata")
    private String accessTokenMetadata;

    @Column(name = "access_token_type", length = 100)
    private String accessTokenType;

    @Column(name = "access_token_scopes", length = 1000)
    private String accessTokenScopes;

    @Column(name = "access_token_app_token", length = 300)
    private String accessTokenAppToken;

    @Column(name = "access_token_user_agent", length = 300)
    private String accessTokenUserAgent;

    @Column(name = "access_token_remote_ip", length = 300)
    private String accessTokenRemoteIp;

    @Lob
    @Column(name = "refresh_token_value")
    private String refreshTokenValue;

    @Column(name = "refresh_token_issued_at")
    private LocalDateTime refreshTokenIssuedAt;

    @Column(name = "refresh_token_expires_at")
    private LocalDateTime refreshTokenExpiresAt;

    @Lob
    @Column(name = "refresh_token_metadata")
    private String refreshTokenMetadata;

    @Lob
    @Column(name = "oidc_id_token_value")
    private String oidcIdTokenValue;

    @Column(name = "oidc_id_token_issued_at")
    private Instant oidcIdTokenIssuedAt;

    @Column(name = "oidc_id_token_expires_at")
    private Instant oidcIdTokenExpiresAt;

    @Lob
    @Column(name = "oidc_id_token_metadata")
    private String oidcIdTokenMetadata;


    @Lob
    @Column(name = "user_code_value")
    private String userCodeValue;

    @Column(name = "user_code_issued_at")
    private Instant userCodeIssuedAt;

    @Column(name = "user_code_expires_at")
    private Instant userCodeExpiresAt;

    @Lob
    @Column(name = "user_code_metadata")
    private String userCodeMetadata;

    @Lob
    @Column(name = "device_code_value")
    private String deviceCodeValue;

    @Column(name = "device_code_issued_at")
    private Instant deviceCodeIssuedAt;

    @Column(name = "device_code_expires_at")
    private Instant deviceCodeExpiresAt;

    @Lob
    @Column(name = "device_code_metadata")
    private String deviceCodeMetadata;



    public void setAccessTokenValue(String accessTokenValue) {
        this.accessTokenValue = CustomAuthenticationKeyGenerator.hashTokenValue(accessTokenValue);
    }
    public void setRefreshTokenValue(String refreshTokenValue) {
        this.refreshTokenValue = CustomAuthenticationKeyGenerator.hashTokenValue(refreshTokenValue);
    }


    public OAuth2Authorization getAttributes() {
        return SerializableObjectConverter.deserializeToAuthentication(attributes);
    }
    public void setAttributes(OAuth2Authorization authorization) {
        this.attributes = SerializableObjectConverter.serializeAuthentication(authorization);
    }
}