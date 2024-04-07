package com.patternknife.securityhelper.oauth2.domain.socialoauth.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.util.Map;

public class SocialVendorOauthDTO {

    //  "kakao_account.profile", "kakao_account.name", "kakao_account.email", "kakao_account.age_range", "kakao_account.birthday", "kakao_account.gender"
    //  {"id":3186198251,"connected_at":"2023-11-26T13:22:07Z","kakao_account":{"has_email":true,"email_needs_agreement":false,"is_email_valid":true,
    //  "is_email_verified":true,"email":"sj60414@nate.com"}}
    @Data
    public static class KaKaoUserInfo {

        private Long id;
        @JsonProperty("connected_at")
        private String connectedAt;
        @JsonProperty("kakao_account")
        private KakaoAccount kakaoAccount;
        private Map<String, String> properties;

        @Data
        public static class KakaoAccount {
            @JsonProperty("has_email")
            private boolean hasEmail;
            @JsonProperty("email_needs_agreement")
            private boolean emailNeedsAgreement;
            private String email;
        }

    }



    @Data
    public static class NaverUserInfo {

        private String resultCode;
        private String message;
        private Response response;

        @Data
        public static class Response {
            private String id; // 동일인 식별 정보
            private String nickname; // 사용자 별명
            private String name; // 사용자 이름
            private String email; // 사용자 메일 주소
            private String gender; // 성별 (F: 여성, M: 남성, U: 확인불가)
            private String age; // 사용자 연령대
            private String birthday; // 사용자 생일 (MM-DD 형식)
            private String profileImage; // 사용자 프로필 사진 URL
            private String birthyear; // 출생연도
            private String mobile; // 휴대전화번호
        }

    }

    @Data
    public static class GoogleUserInfo {
        private String sub;
        private String id;
        private String email;
        private boolean verifiedEmail;
        private String name;
        private String givenName;
        private String familyName;
        private String picture;
        private String locale;
    }

}
