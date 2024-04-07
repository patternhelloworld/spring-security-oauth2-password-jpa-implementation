package com.patternknife.securityhelper.oauth2.domain.socialoauth.bo;

import com.patternknife.securityhelper.oauth2.config.response.error.exception.auth.SocialUnauthorizedException;
import com.patternknife.securityhelper.oauth2.domain.socialoauth.dto.SocialVendorOauthDTO;
import lombok.AllArgsConstructor;
import org.springframework.http.*;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;

@AllArgsConstructor
public class KakaoAuth {

    private RestTemplate kaKaoOpenApiTemplate;

/*    public boolean validateToken(String kaKaoToken) throws IOException {

        HttpURLConnection connection = getConnection(KakaoApiConstants.URLs.VALIDATE_TOKEN_URL, "GET", false);
        connection.setRequestProperty("Authorization", "Bearer " + kaKaoToken);

        int responseCode = connection.getResponseCode();

        if (responseCode == HttpURLConnection.HTTP_OK) { // 200 OK
            String result = getResultString(connection.getInputStream());

            JsonParser jsonParser = new JacksonJsonParser();
            Map<String, Object> map = jsonParser.parseMap(result);
            Long id = (Long) map.get("id");
            Integer expires_in = (Integer) map.get("expires_in");

            return true;
        } else { // not 200
            String result = getResultString(connection.getErrorStream());
            JsonParser jsonParser = new JacksonJsonParser();
            Map<String, Object> map = jsonParser.parseMap(result);
            int code = (int) map.get("code");
            String msg = (String) map.get("msg");

            if (code == -401) {
                throw new InvalidTokenException(msg);
            } else {
                throw new RuntimeException(msg);
            }
        }
    }*/

    // https://developers.kakao.com/docs/latest/ko/kakaologin/rest-api#get-token-info
    public SocialVendorOauthDTO.KaKaoUserInfo getKakaoUserInfo(String kaKaoToken) throws IOException {

        HttpHeaders headers = new HttpHeaders();
     //   headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("Authorization", "Bearer " + kaKaoToken);
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        HttpEntity<String> entity = new HttpEntity<>(headers);


      //  StringJoiner propertyKeysJoiner = new StringJoiner("\",\"", "[\"", "\"]");
      //  propertyKeysJoiner.add("kakao_account.email");
        // Add other property keys as needed
       // String propertyKeys = URLEncoder.encode(propertyKeysJoiner.toString(), String.valueOf(StandardCharsets.UTF_8));

        try {
            ResponseEntity<SocialVendorOauthDTO.KaKaoUserInfo> response = kaKaoOpenApiTemplate.exchange(
                    "/v2/user/me" + "?property_keys=[\"kakao_account.email\"]",
                    HttpMethod.GET,
                    entity,
                    SocialVendorOauthDTO.KaKaoUserInfo.class);
            return response.getBody();
        } catch (HttpClientErrorException.Unauthorized ex) {
            // Handle 401 Unauthorized error
            // You can log this error, return a custom message, etc.
            // For example:
            throw new SocialUnauthorizedException("{\"Kakao\" : " + ex.getMessage() + "}");
        } catch (HttpClientErrorException ex) {
            // Handle other HttpClientErrorExceptions
            // ...
            throw ex;
        }


    }
}
