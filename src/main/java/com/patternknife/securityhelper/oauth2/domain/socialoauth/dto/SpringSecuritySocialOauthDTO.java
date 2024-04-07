package com.patternknife.securityhelper.oauth2.domain.socialoauth.dto;

import com.patternknife.securityhelper.oauth2.domain.customer.entity.Customer;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.time.Instant;
import java.time.LocalDate;
import java.util.UUID;

public class SpringSecuritySocialOauthDTO {

    @Getter
    public static class TokenRequest {

        @NotBlank
        private String clientId;
        @NotBlank
        private String accessToken;

    }

    @Getter
    @AllArgsConstructor
    public static class NonDependentTokenRequest {

        @NotBlank
        private String clientId;

    }

    @Getter
    public static class CreateCustomerRequest {

        @NotBlank
        private String clientId;
        @NotBlank
        private String accessToken;
        private String appToken;


        @NotBlank
        private String hp;
        @NotNull
        private LocalDate birthday;
        @NotBlank
        private String sex;
        @NotBlank
        private String name;
        @NotNull
        private Integer telecomProvider;

        private String ci;
        @NotBlank
        private String di;

        public Customer toEntityWithKakaoIdName(String kakaoIdName) {
            return Customer.builder()
                    .idName(UUID.randomUUID()+ "-" + Instant.now().toString())
                    .kakaoIdName(kakaoIdName)
                    .hp(this.hp)
                    .birthday(this.birthday)
                    .sex(this.sex)
                    .name(this.name)
                    .telecomProvider(this.telecomProvider)
                    .ci(this.ci)
                    .di(this.di)
                    .build();
        }

        public Customer toEntityWithNaverIdName(String naverIdName) {
            return Customer.builder()
                    .idName(UUID.randomUUID()+ "-" + Instant.now().toString())
                    .naverIdName(naverIdName)
                    .hp(this.hp)
                    .birthday(this.birthday)
                    .sex(this.sex)
                    .name(this.name)
                    .telecomProvider(this.telecomProvider)
                    .ci(this.ci)
                    .di(this.di)
                    .build();
        }

        public Customer toEntityWithGoogleIdName(String googleIdName) {
            return Customer.builder()
                    .idName(UUID.randomUUID()+ "-" + Instant.now().toString())
                    .googleIdName(googleIdName)
                    .hp(this.hp)
                    .birthday(this.birthday)
                    .sex(this.sex)
                    .name(this.name)
                    .telecomProvider(this.telecomProvider)
                    .ci(this.ci)
                    .di(this.di)
                    .build();
        }

        public Customer toEntityWithAppleIdName(String appleIdName) {
            return Customer.builder()
                    .idName(UUID.randomUUID()+ "-" + Instant.now().toString())
                    .appleIdName(appleIdName)
                    .hp(this.hp)
                    .birthday(this.birthday)
                    .sex(this.sex)
                    .name(this.name)
                    .telecomProvider(this.telecomProvider)
                    .ci(this.ci)
                    .di(this.di)
                    .build();
        }




    }

    @Getter
    public static class CreateAppleCustomerRequest {

        @NotBlank
        private String clientId;
        @NotBlank
        private String idToken;


        @NotBlank
        private String hp;
        @NotNull
        private LocalDate birthday;
        @NotBlank
        private String sex;
        @NotBlank
        private String name;
        @NotNull
        private Integer telecomProvider;

        private String ci;
        @NotBlank
        private String di;

        public Customer toEntityWithAppleIdName(String appleIdName) {
            return Customer.builder()
                    .idName(UUID.randomUUID() + "-" + Instant.now().toString())
                    .appleIdName(appleIdName)
                    .hp(this.hp)
                    .birthday(this.birthday)
                    .sex(this.sex)
                    .name(this.name)
                    .telecomProvider(this.telecomProvider)
                    .ci(this.ci)
                    .di(this.di)
                    .build();
        }

    }



    @AllArgsConstructor
    @Getter
    public static class TokenResponse {
        private String token_type = "Bearer";
        private String access_token;
        private String refresh_token;
        private int expires_in;
        private String scope;
        private Boolean just_now_created;
        private Boolean password_registered;
    }



    @AllArgsConstructor
    @Getter
    public static class CreateCustomerResponse {
        private Long id;
        private TokenResponse tokenResponse;
        public CreateCustomerResponse(Customer customer, TokenResponse tokenResponse) {
            this.id = customer.getId();
            this.tokenResponse = tokenResponse;
        }
    }
}
