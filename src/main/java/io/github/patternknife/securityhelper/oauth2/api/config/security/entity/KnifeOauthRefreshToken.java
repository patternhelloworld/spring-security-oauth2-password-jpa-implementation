package io.github.patternknife.securityhelper.oauth2.api.config.security.entity;

import io.github.patternknife.securityhelper.oauth2.api.config.security.util.SerializableObjectConverter;
import jakarta.persistence.*;
import lombok.Data;
import org.hibernate.annotations.DynamicUpdate;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;

import java.time.LocalDateTime;

@Table(name="oauth_refresh_token")
@Entity
@Data
@DynamicUpdate
public class KnifeOauthRefreshToken {

    @Id
    @Column(name = "token_id")
    private String tokenId;

    @Lob
    @Column(name = "token", columnDefinition = "NVARCHAR(MAX)")
    private String token;

    @Lob
    @Column(name = "authentication", columnDefinition = "NVARCHAR(MAX)")
    private String authentication;

    @Column(name = "expiration_date")
    private LocalDateTime expirationDate;

    public OAuth2RefreshToken getToken() {
        return SerializableObjectConverter.deserializeToRefreshToken(token);
    }

    public void setToken(OAuth2RefreshToken oAuth2RefreshToken) {
        this.token = SerializableObjectConverter.serializeRefreshToken(oAuth2RefreshToken);
    }

    public OAuth2Authorization getAuthentication() {
        return SerializableObjectConverter.deserializeToAuthentication(authentication);
    }

    public void setAuthentication(OAuth2Authorization authentication) {
        this.authentication = SerializableObjectConverter.serializeAuthentication(authentication);
    }

}