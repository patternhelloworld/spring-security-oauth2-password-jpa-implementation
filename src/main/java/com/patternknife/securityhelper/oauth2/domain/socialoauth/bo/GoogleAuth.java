package com.patternknife.securityhelper.oauth2.domain.socialoauth.bo;

import com.patternknife.securityhelper.oauth2.config.response.error.exception.auth.SocialUnauthorizedException;
import com.patternknife.securityhelper.oauth2.domain.socialoauth.dto.SocialVendorOauthDTO;
import lombok.AllArgsConstructor;
import org.springframework.http.*;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;

@AllArgsConstructor
public class GoogleAuth {

    private RestTemplate googleOpenApiTemplate;

    // 참고 : https://developers.google.com/docs/login/devguide/devguide.md#3-4-5-%EC%A0%91%EA%B7%BC-%ED%86%A0%ED%81%B0%EC%9D%84-%EC%9D%B4%EC%9A%A9%ED%95%98%EC%97%AC-%ED%94%84%EB%A1%9C%ED%95%84-api-%ED%98%B8%EC%B6%9C%ED%95%98%EA%B8%B0
    public SocialVendorOauthDTO.GoogleUserInfo getGoogleUserInfo(String googleToken) throws IOException {

        HttpHeaders headers = new HttpHeaders();
  //      headers.setContentType(MediaType.APPLICATION_JSON);
       // headers.set("Authorization", "Bearer " + googleToken);
       // headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        HttpEntity<String> entity = new HttpEntity<>(headers);

        try {
            ResponseEntity<SocialVendorOauthDTO.GoogleUserInfo> response = googleOpenApiTemplate.exchange(
                    "/tokeninfo?id_token=" + googleToken,
                    HttpMethod.GET,
                    entity,
                    SocialVendorOauthDTO.GoogleUserInfo.class);
            return response.getBody();
        } catch (HttpClientErrorException.Unauthorized ex) {
            // Handle 401 Unauthorized error
            // You can log this error, return a custom message, etc.
            // For example:
            throw new SocialUnauthorizedException("{\"GOOGLE \" : " + ex.getMessage() + "}");
        } catch (HttpClientErrorException ex) {
            // Handle other HttpClientErrorExceptions
            // ...
            throw ex;
        }


    }
}
