package com.patternknife.securityhelper.oauth2.client.domain.admin.dto;

import com.patternknife.securityhelper.oauth2.client.domain.admin.entity.Admin;
import com.patternknife.securityhelper.oauth2.client.domain.admin.entity.Password;
import com.fasterxml.jackson.annotation.JsonFormat;
import com.querydsl.core.annotations.QueryProjection;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.*;

import java.sql.Timestamp;
import java.util.List;

public class AdminDTO {

    @Getter
    @NoArgsConstructor(access = AccessLevel.PROTECTED)
    public static class CreateReq {

        @NotBlank(message = "ID cannot be empty.")
        private String idName;

        @NotBlank(message = "Password cannot be empty.")
        public String password;
        public Boolean otpIssue;

        private List<Integer> commaSplitRoleIds;

        @Builder
        public CreateReq(String idName, String password) {
            this.idName = idName;
            this.password = password;
        }


        public Admin toEntity() {
            return Admin.builder()
                    .idName(this.idName)
                    .password(Password.builder().value(this.password).build())
                    .build();
        }

    }

    @Getter
    @NoArgsConstructor(access = AccessLevel.PROTECTED)
    @AllArgsConstructor
    public static class UpdateReq {

        @NotNull(message = "ID cannot be empty.")
        private Long id;

        @NotBlank(message = "ID cannot be empty.")
        private String idName;

        private List<Integer> commaSplitRoleIds;


        public String password;
        public Boolean otpIssue;
    }

    @Getter
    public static class CreateRes {

        private Long id;

        public CreateRes(Admin admin) {
            this.id = admin.getId();
        }
    }

    @Getter
    public static class UpdateRes {

        private Long id;
        private String idName;

        public UpdateRes(Admin admin) {
            this.id = admin.getId();
            this.idName = admin.getIdName();
        }
    }

    @Getter
    public static class OneWithRoleIdsRes {

        private Long id;
        private String idName;
        private String description;
        private String commaSplitRoleIds;

        @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd HH:mm:ss", timezone = "Asia/Seoul")
        private Timestamp createdAt;
        @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd HH:mm:ss", timezone = "Asia/Seoul")
        private Timestamp updatedAt;

        @QueryProjection
        public OneWithRoleIdsRes(Long id, String idName, String description, String commaSplitRoleIds, Timestamp createdAt, Timestamp updatedAt) {
            this.id = id;
            this.idName = idName;
            this.description = description;
            this.commaSplitRoleIds = commaSplitRoleIds;
            this.createdAt = createdAt;
            this.updatedAt = updatedAt;
        }
    }

    @Getter
    public static class CurrentOneWithSessionRemainingSecondsRes {

        private Long id;
        private String idName;
        private Integer accessTokenRemainingSeconds;
        private String commaSplitRoleIds;

        @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd HH:mm:ss", timezone = "Asia/Seoul")
        private Timestamp createdAt;
        @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd HH:mm:ss", timezone = "Asia/Seoul")
        private Timestamp updatedAt;

        public CurrentOneWithSessionRemainingSecondsRes(OneWithRoleIdsRes oneWithRoleIdsRes, Integer accessTokenRemainingSeconds) {
            this.id = oneWithRoleIdsRes.getId();
            this.idName = oneWithRoleIdsRes.getIdName();
            this.commaSplitRoleIds = oneWithRoleIdsRes.getCommaSplitRoleIds();
            this.accessTokenRemainingSeconds = accessTokenRemainingSeconds;
            this.createdAt = oneWithRoleIdsRes.getCreatedAt();
            this.updatedAt = oneWithRoleIdsRes.getUpdatedAt();
        }
    }

}
