package com.patternknife.securityhelper.oauth2.domain.traditionaloauth.bo;

import java.util.Base64;
import java.util.Optional;

public class BasicTokenResolver {

    public static Optional<BasicCredentials> parse(String authHeader) {
        if (authHeader != null && authHeader.startsWith("Basic ")) {
            // "Basic " 다음의 문자열을 추출
            String base64Credentials = authHeader.substring("Basic ".length()).trim();
            // Base64 디코딩
            byte[] credDecoded = Base64.getDecoder().decode(base64Credentials);
            String credentials = new String(credDecoded);

            // 콜론으로 클라이언트 ID와 시크릿 분리
            final String[] values = credentials.split(":", 2);
            if (values.length == 2) {
                return Optional.of(new BasicCredentials(values[0], values[1]));
            }
        }
        return Optional.empty();
    }

    public static class BasicCredentials {
        private final String clientId;
        private final String clientSecret;

        public BasicCredentials(String clientId, String clientSecret) {
            this.clientId = clientId;
            this.clientSecret = clientSecret;
        }

        // 게터
        public String getClientId() {
            return clientId;
        }

        public String getClientSecret() {
            return clientSecret;
        }
    }
}
