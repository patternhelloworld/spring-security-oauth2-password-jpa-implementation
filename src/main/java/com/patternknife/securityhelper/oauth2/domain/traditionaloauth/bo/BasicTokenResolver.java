package com.patternknife.securityhelper.oauth2.domain.traditionaloauth.bo;

import java.util.Base64;
import java.util.Optional;

public class BasicTokenResolver {

    public static Optional<BasicCredentials> parse(String authHeader) {
        if (authHeader != null && authHeader.startsWith("Basic ")) {

            String base64Credentials = authHeader.substring("Basic ".length()).trim();

            byte[] credDecoded = Base64.getDecoder().decode(base64Credentials);
            String credentials = new String(credDecoded);


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


        public String getClientId() {
            return clientId;
        }

        public String getClientSecret() {
            return clientSecret;
        }
    }
}
