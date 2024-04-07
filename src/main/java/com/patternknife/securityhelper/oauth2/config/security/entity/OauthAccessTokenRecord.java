package com.patternknife.securityhelper.oauth2.config.security.entity;

import jakarta.persistence.*;
import lombok.Data;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.DynamicUpdate;
import org.hibernate.annotations.UpdateTimestamp;

import java.io.Serializable;
import java.sql.Timestamp;

@Table(name="oauth_access_token_record")
@Entity
@Data
@DynamicUpdate
@IdClass(OauthAccessTokenRecord.OAuthAccessTokenUserAgentRecordId.class)
public class OauthAccessTokenRecord {

    @Id
    @Column(name = "user_name", nullable = false, length = 255)
    private String userName;
    @Id
    @Column(name = "user_agent", nullable = false, length = 500)
    private String userAgent;

    @Column(name = "device_type")
    private Integer deviceType;

    @Column(name="created_at", updatable = false)
    @CreationTimestamp
    private Timestamp createdAt;

    @Column(name="updated_at")
    @UpdateTimestamp
    private Timestamp updatedAt;

    // 생성자, 게터, 세터
    @Data
    public static class OAuthAccessTokenUserAgentRecordId implements Serializable {
        private String userName;
        private String userAgent;

        // 생성자, 게터, 세터, equals, hashCode
    }

}