package com.patternknife.securityhelper.oauth2.domain.customer.dto;

import com.patternknife.securityhelper.oauth2.domain.customer.entity.Customer;
import com.patternknife.securityhelper.oauth2.domain.point.entity.PointDetail;
import com.patternknife.securityhelper.oauth2.domain.socialoauth.dto.SpringSecuritySocialOauthDTO;
import com.patternknife.securityhelper.oauth2.util.CustomUtils;
import com.fasterxml.jackson.annotation.JsonFormat;
import com.querydsl.core.annotations.QueryProjection;
import lombok.Getter;
import lombok.Setter;

import java.sql.Timestamp;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;

public class CustomerResDTO {

    @Getter
    public static class IdWithTokenResponse {
        private Long id;
        private SpringSecuritySocialOauthDTO.TokenResponse tokenResponse;
        public IdWithTokenResponse(Customer customer, SpringSecuritySocialOauthDTO.TokenResponse tokenResponse) {
            this.id = customer.getId();
            this.tokenResponse = tokenResponse;
        }
    }


    @Getter
    public static class OneWithResources {

        private Long id;
        private String idName;
        private String email;
        private String name;
        private String hp;


        @Setter
        private Long point;
        private Long availableGiftCounts;
        private Long treatmentCounts;

        @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd HH:mm:ss", timezone = "Asia/Seoul")
        private Timestamp createdAt;
        @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd HH:mm:ss", timezone = "Asia/Seoul")
        private Timestamp updatedAt;


        @QueryProjection
        public OneWithResources(Long id, String idName, String email, String name, String hp, Long point, Long availableGiftCounts, Long treatmentCounts, Timestamp createdAt, Timestamp updatedAt) {

            this.id = id;
            this.idName = idName;
            this.email = email;
            this.name = name;
            this.hp =hp;
            this.point = point;
            this.availableGiftCounts = availableGiftCounts;
            this.treatmentCounts = treatmentCounts;

            this.createdAt = createdAt;
            this.updatedAt = updatedAt;
        }
    }

    @Getter
    public static class OneWithInterestedTreatmentParts {

        private Long id;
        private Long interestedTreatmentId;

        private int upperPart;
        private int middlePart;
        private int lowerPart;

        @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd HH:mm:ss", timezone = "Asia/Seoul")
        private Timestamp createdAt;
        @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd HH:mm:ss", timezone = "Asia/Seoul")
        private Timestamp updatedAt;

        @QueryProjection
        public OneWithInterestedTreatmentParts(Long id, Long interestedTreatmentId, int upperPart, int middlePart, int lowerPart, Timestamp createdAt, Timestamp updatedAt) {
            this.id = id;
            this.interestedTreatmentId = interestedTreatmentId;
            this.upperPart = upperPart;
            this.middlePart = middlePart;
            this.lowerPart = lowerPart;
            this.createdAt = createdAt;
            this.updatedAt = updatedAt;
        }
    }

    @Getter
    public static class Id {
        private Long id;

        public Id(Long id) {
            this.id = id;
        }
        public Id(Customer customer) {
            this.id = customer.getId();
        }
    }

    @Getter
    public static class IdAdminId {
        private Long id;
        private Long adminId;

        public IdAdminId(Long id, Long adminId) {
            this.id = id;
            this.adminId = adminId;
        }
    }

    @Getter
    @Setter
    public static class OneWithCountsWithAdmin {

        private Long id;

        private String email;
        private String name;
        private String idName;

        private String hp;
        private LocalDate birthday;
        private String sex;


        // 비즈니스 로직 파트
        private Long currentPoint;

        private Long treatmentCounts;
        private Long giftCounts;

        private Long interestedTreatmentPartCounts;

        private String kakaoIdName;
        private String naverIdName;
        private String googleIdName;
        private String appleIdName;

        // 추후 사용
        private LocalDateTime passwordChangedAt;

        @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd HH:mm:ss", timezone = "Asia/Seoul")
        private Timestamp createdAt;

        private Long createAdminId;

        @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd HH:mm:ss", timezone = "Asia/Seoul")
        private Timestamp updatedAt;

        private Long updateAdminId;

        @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd HH:mm:ss", timezone = "Asia/Seoul")
        private LocalDateTime deletedAt;

        private Long deleteAdminId;

        @QueryProjection
        public OneWithCountsWithAdmin(Long id, String email, String name, String idName, String hp, LocalDate birthday, String sex,
                                      Long currentPoint, Long treatmentCounts, Long giftCounts, Long interestedTreatmentPartCounts,
                                      String kakaoIdName, String naverIdName, String googleIdName, String appleIdName, LocalDateTime passwordChangedAt,
                                      Timestamp createdAt, Timestamp updatedAt, LocalDateTime deletedAt, Long deleteAdminId) {
            this.id = id;
            this.email = email;
            this.name = name;
            this.idName = idName;
            this.hp = hp;
            this.birthday = birthday;
            this.sex = sex;
            this.currentPoint = currentPoint;
            this.treatmentCounts = treatmentCounts;
            this.giftCounts = giftCounts;
            this.interestedTreatmentPartCounts = interestedTreatmentPartCounts;
            this.kakaoIdName = kakaoIdName;
            this.naverIdName = naverIdName;
            this.googleIdName = googleIdName;
            this.appleIdName = appleIdName;
            this.passwordChangedAt = passwordChangedAt;
            this.createdAt = createdAt;
            this.updatedAt = updatedAt;
            this.deletedAt = deletedAt;
            this.deleteAdminId = deleteAdminId;
        }
    }

    @Setter
    @Getter
    public static class IdNameWithPointDetailCreatedAtEarnedSum {

        private Long id;

        private String createdAtGrouped;
        private Long pointEarnedSum;

        private String customerName;

        @QueryProjection
        public IdNameWithPointDetailCreatedAtEarnedSum(Long id, String createdAtGrouped, Long pointEarnedSum, String customerName) {
            this.id = id;
            this.createdAtGrouped = createdAtGrouped;
            this.pointEarnedSum = pointEarnedSum;
            this.customerName = customerName;
        }
    }

    @Getter
    public static class OneWithPointDetails {

        private Long id;
        private List<PointDetail> pointDetails;

        @QueryProjection
        public OneWithPointDetails(Long id, List<PointDetail> pointDetails) {

            this.id = id;
            this.pointDetails = pointDetails;
        }
    }



    @Getter
    @Setter
    public static class IdWithGiftRequestDatePointPriceSum {

        private Long id;

        //@JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd", timezone = "Asia/Seoul")
        private String requestDateGrouped;

        private String customerName;

        private Long giftPointSum;
        private Long giftPriceSum;


        @QueryProjection
        public IdWithGiftRequestDatePointPriceSum(Long id, String requestDateGrouped, String customerName, Long giftPointSum, Long giftPriceSum) {
            this.id = id;
            this.requestDateGrouped = requestDateGrouped;
            this.customerName = customerName;
            this.giftPointSum = giftPointSum;
            this.giftPriceSum = giftPriceSum;
        }
    }

    @Getter
    public static class IdNamesCreatedAt {
        private Long id;
        private String idName;
        private Boolean existPassword;
        private String kakaoIdName;
        private String naverIdName;
        private String googleIdName;
        private String appleIdName;
        @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd", timezone = "Asia/Seoul")
        private Timestamp createdAt;

        public IdNamesCreatedAt(Customer customer) {
            this.id = customer.getId();
            this.idName = CustomUtils.maskIdName(customer.getIdName());
            this.existPassword = (customer.getPassword() != null);
            this.kakaoIdName = customer.getKakaoIdName();
            this.naverIdName = customer.getNaverIdName();
            this.googleIdName = customer.getGoogleIdName();
            this.appleIdName = customer.getAppleIdName();
            this.createdAt = customer.getCreatedAt();
        }
    }


    @Getter
    public static class IdNameWithAccessTokenRemainingSeconds {

        private Long id;
        private String idName;
        private String name;
        private String email;
        private Integer accessTokenRemainingSeconds;

        @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd HH:mm:ss", timezone = "Asia/Seoul")
        private Timestamp createdAt;
        @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd HH:mm:ss", timezone = "Asia/Seoul")
        private Timestamp updatedAt;

        public IdNameWithAccessTokenRemainingSeconds(Customer customer, Integer accessTokenRemainingSeconds) {
            this.id = customer.getId();
            this.idName = customer.getIdName();
            this.name = customer.getName();
            this.email = customer.getEmail();
            this.accessTokenRemainingSeconds = accessTokenRemainingSeconds;
            this.createdAt = customer.getCreatedAt();
            this.updatedAt = customer.getUpdatedAt();
        }
    }

    @Getter
    public static class SensitiveInfoAgreeWithPushAgrees {
        private Long customerId;
        private String sensitiveInfo;
        @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd HH:mm:ss", timezone = "Asia/Seoul")
        private Timestamp sensitiveInfoCreatedAt;
        @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd HH:mm:ss", timezone = "Asia/Seoul")
        private LocalDateTime sensitiveInfoUpdatedAt;

        private Integer pushAgree;
        private Integer nightPushAgree;
        @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd HH:mm:ss", timezone = "Asia/Seoul")
        private LocalDateTime pushCreatedAt;
        @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd HH:mm:ss", timezone = "Asia/Seoul")
        private LocalDateTime pushUpdatedAt;

        @QueryProjection
        public SensitiveInfoAgreeWithPushAgrees(Long customerId, String sensitiveInfo, Timestamp sensitiveInfoCreatedAt, LocalDateTime sensitiveInfoUpdatedAt, Integer pushAgree, Integer nightPushAgree, LocalDateTime pushCreatedAt, LocalDateTime pushUpdatedAt) {
            this.customerId = customerId;
            this.sensitiveInfo = sensitiveInfo;
            this.sensitiveInfoCreatedAt = sensitiveInfoCreatedAt;
            this.sensitiveInfoUpdatedAt = sensitiveInfoUpdatedAt;
            this.pushAgree = pushAgree;
            this.nightPushAgree = nightPushAgree;
            this.pushCreatedAt = pushCreatedAt;
            this.pushUpdatedAt = pushUpdatedAt;
        }
    }

}

