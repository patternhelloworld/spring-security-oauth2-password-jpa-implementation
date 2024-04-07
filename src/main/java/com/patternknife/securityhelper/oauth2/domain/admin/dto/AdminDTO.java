package com.patternknife.securityhelper.oauth2.domain.admin.dto;

import com.patternknife.securityhelper.oauth2.domain.admin.entity.Admin;
import com.patternknife.securityhelper.oauth2.domain.admin.entity.Password;
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

        @NotBlank(message = "ID는 비어있으면 안됩니다.")
        private String idName;

        @NotBlank(message = "비밀번호는 비어있으면 안됩니다.")
        public String password;
        public Boolean otpIssue;

        private List<Integer> commaSplitRoleIds;

        @Builder
        public CreateReq(String idName, String password) {
            this.idName = idName;
            this.password = password;
        }


        public Admin toEntity(String otpSecretKey, String otpSecretQrUrl) {
            return Admin.builder()
                    .idName(this.idName)
                    .password(Password.builder().value(this.password).build())
                    .otpSecretKey(otpSecretKey)
                    .otpSecretQrUrl(otpSecretQrUrl)
                    .build();
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

        @NotNull(message = "고유 ID 값을 확인할 수 없습니다. 문제가 지속되면 관리자에게 문의 하십시오.")
        private Long id;

        @NotBlank(message = "ID는 비어있으면 안됩니다.")
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

        private String otpSecretKey;
        private String otpSecretQrUrl;

        public UpdateRes(Admin admin) {
            this.id = admin.getId();
            this.idName = admin.getIdName();
            this.otpSecretKey = admin.getOtpSecretKey();
            this.otpSecretQrUrl = admin.getOtpSecretQrUrl();
        }
    }

    @Getter
    public static class OneWithRoleIdsRes {

        private Long id;
        private String idName;
        private String otpSecretKey;
        private String otpSecretQrUrl;
        private String description;
        private String commaSplitRoleIds;

        @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd HH:mm:ss", timezone = "Asia/Seoul")
        private Timestamp createdAt;
        @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd HH:mm:ss", timezone = "Asia/Seoul")
        private Timestamp updatedAt;

        @QueryProjection
        public OneWithRoleIdsRes(Long id, String idName, String otpSecretKey, String otpSecretQrUrl, String description, String commaSplitRoleIds, Timestamp createdAt, Timestamp updatedAt) {
            this.id = id;
            this.idName = idName;
            this.otpSecretKey = otpSecretKey;
            this.otpSecretQrUrl = otpSecretQrUrl;
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
