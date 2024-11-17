package io.github.patternknife.securityhelper.oauth2.api.config.security.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.DynamicUpdate;

import java.time.Instant;

@Entity
@Table(name = "oauth2_registered_client")
@Getter
@Setter
public class KnifeClient {

    // UUID.randomUUID().toString() (refer to 'Spring-Authorization-Server')
    @Id
    @Column(name = "id", length = 100)
    private String id;

    @Column(name = "client_id", length = 100, nullable = false)
    private String clientId;

    @Column(name = "client_id_issued_at", nullable = false, columnDefinition = "TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
    private Instant clientIdIssuedAt;

    @Column(name = "client_secret", length = 200)
    private String clientSecret;

    @Column(name = "client_secret_expires_at")
    private Instant clientSecretExpiresAt;

    @Column(name = "client_name", length = 200, nullable = false)
    private String clientName;

    @Column(name = "client_authentication_methods", length = 1000, nullable = false)
    private String clientAuthenticationMethods;

    @Column(name = "authorization_grant_types", length = 1000, nullable = false)
    private String authorizationGrantTypes;

    @Column(name = "redirect_uris", length = 1000)
    private String redirectUris;

    @Column(name = "post_logout_redirect_uris", length = 1000)
    private String postLogoutRedirectUris;

    @Column(name = "scopes", length = 1000, nullable = false)
    private String scopes;

    @Column(name = "client_settings", length = 2000, nullable = false)
    private String clientSettings;

    @Column(name = "token_settings", length = 2000, nullable = false)
    private String tokenSettings;

    @Override
    public String toString() {
        return "KnifeClient{" +
                "id='" + id + '\'' +
                ", clientId='" + clientId + '\'' +
                ", clientIdIssuedAt=" + clientIdIssuedAt +
                ", clientSecret='" + clientSecret + '\'' +
                ", clientSecretExpiresAt=" + clientSecretExpiresAt +
                ", clientName='" + clientName + '\'' +
                ", clientAuthenticationMethods='" + clientAuthenticationMethods + '\'' +
                ", authorizationGrantTypes='" + authorizationGrantTypes + '\'' +
                ", redirectUris='" + redirectUris + '\'' +
                ", postLogoutRedirectUris='" + postLogoutRedirectUris + '\'' +
                ", scopes='" + scopes + '\'' +
                ", clientSettings='" + clientSettings + '\'' +
                ", tokenSettings='" + tokenSettings + '\'' +
                '}';
    }
}