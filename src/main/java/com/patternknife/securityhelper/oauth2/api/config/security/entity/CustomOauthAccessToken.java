package com.patternknife.securityhelper.oauth2.api.config.security.entity;

import com.patternknife.securityhelper.oauth2.api.config.security.util.SerializableObjectConverter;
import jakarta.persistence.*;
import lombok.Data;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.DynamicUpdate;
import org.hibernate.annotations.UpdateTimestamp;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;

import java.sql.Timestamp;
import java.time.LocalDateTime;

@Table(name="oauth_access_token")
@Entity
@Data
@DynamicUpdate
public class CustomOauthAccessToken {

    // MD5(accessToken string)
    @Column(name = "token_id")
    private String tokenId;

    // MD5(username + client_id + app_token)
    @Id
    @Column(name = "authentication_id")
    private String authenticationId;

    // Base64(Serialize(Oauth2AccessToken))
    @Lob
    @Column(name = "token", columnDefinition = "NVARCHAR(MAX)")
    private String token;

    @Column(name = "user_name")
    private String userName;

    @Column(name = "client_id")
    private String clientId;

    // Base64(Serialize(Oauth2Authorization))
    @Lob
    @Column(name = "authentication", columnDefinition = "NVARCHAR(MAX)")
    private String authentication;

    @Column(name = "refresh_token")
    private String refreshToken;

    @Column(name = "app_token")
    private String appToken;

    @Column(name = "user_agent")
    private String userAgent;

    @Column(name = "remote_ip")
    private String remoteIp;

    @Column(name = "expiration_date")
    private LocalDateTime expirationDate;

    @Column(name="created_at", updatable = false)
    @CreationTimestamp
    private Timestamp createdAt;

    @Column(name="updated_at")
    @UpdateTimestamp
    private Timestamp updatedAt;

    public OAuth2AccessToken getToken() {
        return SerializableObjectConverter.deserializeToAccessToken(token);
    }

    public void setToken(OAuth2AccessToken oAuth2AccessToken) {
        this.token = SerializableObjectConverter.serializeAccessToken(oAuth2AccessToken);
    }

    public OAuth2Authorization getAuthentication() {
       return SerializableObjectConverter.deserializeToAuthentication(authentication);
    }

    public void setAuthentication(OAuth2Authorization authorization) {
        this.authentication = SerializableObjectConverter.serializeAuthentication(authorization);
    }

}