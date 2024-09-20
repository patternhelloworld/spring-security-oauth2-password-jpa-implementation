package io.github.patternknife.securityhelper.oauth2.api.domain.traditionaloauth.dto;

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

        @NotBlank
        private String grant_type;

        private String otp_value;

    }

    @Getter
    @Setter
    public static class AuthorizationCodeRequest {

        private String username;
        private String password;

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


    public static class AuthorizationCodeResponse {
        private String authorization_code;

        public AuthorizationCodeResponse(String authorizationCode) {
            this.authorization_code = authorizationCode;
        }

        public String getAuthorizationCode() {
            return authorization_code;
        }

        public void setAuthorizationCode(String authorizationCode) {
            this.authorization_code = authorizationCode;
        }

    }



}
