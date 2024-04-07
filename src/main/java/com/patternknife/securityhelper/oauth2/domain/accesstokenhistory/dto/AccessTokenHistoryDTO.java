package com.patternknife.securityhelper.oauth2.domain.accesstokenhistory.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.querydsl.core.annotations.QueryProjection;
import lombok.Getter;

import java.sql.Timestamp;
import java.time.LocalDateTime;

public class AccessTokenHistoryDTO {
    @Getter
    public static class AccessTokenWithCustomerRes {

        private String authenticationId;

        private String userName;
        private String appToken;
        private String userAgent;
        private String remoteIp;
        private Long customerId;

        @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd HH:mm:ss", timezone = "Asia/Seoul")
        private LocalDateTime accessTokenExpirationDate;
        @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd HH:mm:ss", timezone = "Asia/Seoul")
        private LocalDateTime refreshTokenExpirationDate;

        @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd HH:mm:ss", timezone = "Asia/Seoul")
        private Timestamp createdAt;

        @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd HH:mm:ss", timezone = "Asia/Seoul")
        private Timestamp updatedAt;

        @QueryProjection
        public AccessTokenWithCustomerRes(String authenticationId, String userName, String appToken, String userAgent, String remoteIp, Long customerId,
                                          LocalDateTime accessTokenExpirationDate, LocalDateTime refreshTokenExpirationDate,
                                          Timestamp createdAt, Timestamp updatedAt) {
            this.authenticationId = authenticationId;
            this.userName = userName;
            this.appToken = appToken;
            this.userAgent = userAgent;
            this.remoteIp = remoteIp;
            this.customerId = customerId;
            this.accessTokenExpirationDate = accessTokenExpirationDate;
            this.refreshTokenExpirationDate = refreshTokenExpirationDate;
            this.createdAt = createdAt;
            this.updatedAt = updatedAt;
        }
    }
    @Getter
    public static class AccessTokenRecordWithCustomerRes {

        private String userName;
        private String userAgent;

        @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd HH:mm:ss", timezone = "Asia/Seoul")
        private Timestamp createdAt;
        @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd HH:mm:ss", timezone = "Asia/Seoul")
        private Timestamp updatedAt;

        @QueryProjection
        public AccessTokenRecordWithCustomerRes(String userName, String userAgent, Timestamp createdAt, Timestamp updatedAt) {
            this.userName = userName;
            this.userAgent = userAgent;
            this.createdAt = createdAt;
            this.updatedAt = updatedAt;
        }
    }
}
