package com.patternknife.securityhelper.oauth2.domain.traditionaloauth.dto;

import com.patternknife.securityhelper.oauth2.domain.customer.entity.Customer;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;


public class SpringSecurityTraditionalOauthDTO {

    @Getter
    @Setter
    public static class TokenRequest {

        private String username;
        private String password;

        private String refresh_token;

        @NotBlank(message = "grant_type 필드는 비어있으면 안됩니다.")
        private String grant_type;

        private String otp_value;

    }


    @AllArgsConstructor
    @Getter
    public static class TokenResponse {
        private String access_token;
        private String token_type = "Bearer";
        private String refresh_token;
        private int expires_in;
        private String scope;
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
