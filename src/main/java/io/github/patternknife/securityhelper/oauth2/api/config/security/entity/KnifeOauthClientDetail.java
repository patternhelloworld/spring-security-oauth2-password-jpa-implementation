package io.github.patternknife.securityhelper.oauth2.api.config.security.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Data;
import org.hibernate.annotations.DynamicUpdate;



@Table(name="oauth_client_details")
@Entity
@Data
@DynamicUpdate
public class KnifeOauthClientDetail {
    @Id
    @Column(name = "client_id")
    private String clientId;

    @Column(name = "client_secret")
    private String clientSecret;

    @Column(name = "scope")
    private String scope;

    @Column(name = "authorized_grant_types")
    private String authorizedGrantTypes;

    @Column(name = "resource_ids")
    private String resourceIds;

    @Column(name = "access_token_validity")
    private Long accessTokenValidity;

    @Column(name = "refresh_token_validity")
    private Long refreshTokenValidity;

}