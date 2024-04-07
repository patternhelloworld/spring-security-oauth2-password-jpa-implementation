package com.patternknife.securityhelper.oauth2.domain.customer.dto;

import com.patternknife.securityhelper.oauth2.domain.customer.entity.Customer;
import com.patternknife.securityhelper.oauth2.domain.customer.entity.Password;
import com.patternknife.securityhelper.oauth2.domain.customer.entity.SensitiveInfoAgreeHistory;
import com.patternknife.securityhelper.oauth2.domain.push.entity.PushAgree;
import com.patternknife.securityhelper.oauth2.domain.push.entity.PushAgreeHistory;
import com.patternknife.securityhelper.oauth2.util.CustomUtils;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Past;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDate;
import java.time.LocalDateTime;

public class CustomerReqDTO {

    @Getter
    public static class CreateSocialNew {
        @NotBlank(message = "이메일은 비어있으면 안됩니다.")
        private String idName;
    }

    @Getter
    public static class Create {
        public String appToken;

        @NotBlank(message = "이름은 비어있으면 안됩니다.")
        public String name;

        @NotNull(message = "생일은 비어있으면 안됩니다.")
        @Past(message = "생일은 과거 날짜여야 합니다.")
        private LocalDate birthday;

        @NotBlank(message = "성별은 비어있으면 안됩니다.")
        private String sex;

        @NotBlank(message = "핸드폰번호는 비어있으면 안됩니다.")
        private String hp;
        private Integer telecomProvider;

        private String idName;
        private String kakaoIdName;
        private String naverIdName;
        private String googleIdName;
        private String appleIdName;

        @NotBlank(message = "PW는 비어있으면 안됩니다.")
        private String password;
        private String email;

        @NotBlank(message = "")
        private String ci;
        @NotBlank(message = "")
        private String di;

        public Customer toEntity() {
            Customer.CustomerBuilder builder = Customer.builder()
                    .name(this.name)
                    .birthday(this.birthday)
                    .sex(this.sex)
                    .hp(CustomUtils.removeSpecialCharacters(this.hp))
                    .telecomProvider(this.telecomProvider)
                    .idName(this.idName)
                    .kakaoIdName(this.kakaoIdName)
                    .naverIdName(this.naverIdName)
                    .googleIdName(this.googleIdName)
                    .appleIdName(this.appleIdName)
                    .password(Password.builder().value(this.password).build())
                    .email(this.email)
                    .ci(this.ci)
                    .di(this.di);
            return builder.build();
        }
    }


    @Getter
    @NoArgsConstructor(access = AccessLevel.PROTECTED)
    @AllArgsConstructor
    public static class Update {

        @NotBlank(message = "아이디는 비어있으면 안됩니다.")
        private String idName;
        @NotBlank(message = "이름은 비어있으면 안됩니다.")
        public String name;
        @NotBlank(message = "헨드폰 번호는 비어있으면 안됩니다.")
        public String hp;

        public String email;

    }

    @Getter
    public static class UpdateSensitiveInfoWithPushAgrees {
        @NotNull(message = "민감정보 필수.")
        private String sensitiveInfo;
        @NotNull(message = "푸시동의 필수.")
        private Integer pushAgree;
        @NotNull(message = "야간동의 필수.")
        private Integer nightPushAgree;

        public PushAgree toEntity(Customer customer) {
            return PushAgree.builder()
                    .customer(customer)
                    .pushAgree(this.pushAgree)
                    .nightPushAgree(this.nightPushAgree)
                    .build();
        }

        public PushAgree toEntity(PushAgree pushAgree) {
            return PushAgree.builder()
                    .id(pushAgree.getId())
                    .pushAgree(this.pushAgree)
                    .nightPushAgree(this.nightPushAgree)
                    .updatedAt(LocalDateTime.now())
                    .build();
        }

        public PushAgreeHistory toPushAgreeHistoryEntity(Long customerId) {
            return PushAgreeHistory.builder()
                    .customerId(customerId)
                    .pushAgree(this.pushAgree)
                    .nightPushAgree(this.nightPushAgree)
                    .build();
        }

        public SensitiveInfoAgreeHistory toSensitiveInfoAgreeHistoryEntity(Long customerId) {
            return SensitiveInfoAgreeHistory.builder()
                    .customerId(customerId)
                    .sensitiveInfoAgree(this.sensitiveInfo)
                    .build();
        }
    }

    @Getter
    public static class UpdatePasswordAndEmail {
        @NotBlank(message = "패스워드는 비어있으면 안됩니다.")
        private String password;
        public String email;
    }

}

