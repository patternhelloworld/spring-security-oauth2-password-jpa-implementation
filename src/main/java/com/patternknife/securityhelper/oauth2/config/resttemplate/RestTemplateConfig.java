package com.patternknife.securityhelper.oauth2.config.resttemplate;

import com.patternknife.securityhelper.oauth2.config.logger.module.RestTemplateClientErrorLogConfig;
import com.patternknife.securityhelper.oauth2.config.logger.module.RestTemplateClientLogConfig;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.BufferingClientHttpRequestFactory;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

import java.time.Duration;

@Configuration
@RequiredArgsConstructor
public class RestTemplateConfig {

    private final RestTemplateBuilder restTemplateBuilder;

    private RestTemplate createRestTemplate(String rootUri) {
        return restTemplateBuilder
                .requestFactory(() -> new BufferingClientHttpRequestFactory(new SimpleClientHttpRequestFactory()))
                .rootUri(rootUri)
                .additionalInterceptors(new RestTemplateClientLogConfig())
                .errorHandler(new RestTemplateClientErrorLogConfig())
                .setConnectTimeout(Duration.ofSeconds(6))
                .build();
    }

    @Bean
    public RestTemplate kaKaoAccessTokenInfoTemplate() {
        return createRestTemplate("https://kapi.kakao.com/v1/user/access_token_info");
    }


    @Bean(name = "kaKaoOpenApiTemplate")
    public RestTemplate kaKaoOpenApiTemplate() {
      return createRestTemplate("https://kapi.kakao.com");
    }

    @Bean(name = "naverOpenApiTemplate")
    public RestTemplate naverOpenApiTemplate() {
        return createRestTemplate("https://openapi.naver.com");
    }

    @Bean(name = "googleOpenApiTemplate")
    public RestTemplate googleOpenApiTemplate() {
        return createRestTemplate("https://oauth2.googleapis.com");
    }


    @Bean(name = "appleOpenApiTemplate")
    public RestTemplate appleOpenApiTemplate() {
        return createRestTemplate("https://appleid.apple.com/auth/token");
    }

    @Bean(name = "appleOpenApiTemplate2")
    public RestTemplate appleOpenApiTemplate2() {
        return createRestTemplate("https://appleid.apple.com/auth/keys");
    }

    @Bean(name = "daouApiTemplate")
    public RestTemplate daouApiTemplate() {
        return createRestTemplate("https://atomtest.donutbook.co.kr:14076/b2ccoupon");
    }

}
