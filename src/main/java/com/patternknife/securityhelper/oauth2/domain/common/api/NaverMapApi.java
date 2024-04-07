package com.patternknife.securityhelper.oauth2.domain.common.api;

import com.patternknife.securityhelper.oauth2.config.response.GlobalSuccessPayload;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;

import javax.net.ssl.SSLException;

@RestController
@RequestMapping("/api/v1/maps")
public class NaverMapApi {

    @Value("${app.naver.map.client.id}")
    private String clientId;
    @Value("${app.naver.map.client.secret}")
    private String clientSecret;

    private WebClient webClient;

    private void createWebClient(String uri){
        String uriPath = "https://naveropenapi.apigw.ntruss.com" + uri;

        HttpClient httpClient = HttpClient.create().secure(t -> {
            try {
                t.sslContext(SslContextBuilder.forClient().trustManager(InsecureTrustManagerFactory.INSTANCE).build());
            } catch (SSLException e) {
                throw new RuntimeException("SSL Context Error", e);
            }
        });

        this.webClient = WebClient.builder()
                .baseUrl(uriPath)
                .clientConnector(new ReactorClientHttpConnector(httpClient))
                .build();
    }

    // https://api.ncloud-docs.com/docs/ai-naver-mapsreversegeocoding-gc
    @GetMapping("/reverse-geocodes/me")
    public GlobalSuccessPayload<?> getReverseGeocodes(@RequestParam(value = "latitude", required = true) final String latitude,
                                                      @RequestParam(value = "longitude", required = true) final String longitude) {

        createWebClient("/map-reversegeocode/v2/gc");

        return new GlobalSuccessPayload<>(this.webClient.get()
                .uri(uriBuilder -> uriBuilder.path("")
                        .queryParam("coords", longitude + "," + latitude)
                        .queryParam("orders", "addr")
                        .queryParam("output", "json")
                        .build())
                .header("X-NCP-APIGW-API-KEY-ID", clientId)
                .header("X-NCP-APIGW-API-KEY", clientSecret)
                .retrieve()
                .bodyToMono(String.class)
                .block());
    }


    @GetMapping("/geocodes/me")
    public GlobalSuccessPayload<?> getGeocodes(@RequestParam(value = "query") final String query,
                                @RequestParam(value = "latitude", required = false, defaultValue = "0") final String latitude,
                                @RequestParam(value = "longitude", required = false, defaultValue = "0") final String longitude) {

        createWebClient("/map-geocode/v2/geocode");

        return new GlobalSuccessPayload<>(this.webClient.get()
                .uri(uriBuilder -> uriBuilder.path("")
                        .queryParam("query", query)
                        .queryParam("coordinate", longitude + "," + latitude)
                        .queryParam("orders", "addr")
                        .queryParam("output", "json")
                        .build())
                .header("X-NCP-APIGW-API-KEY-ID", clientId)
                .header("X-NCP-APIGW-API-KEY", clientSecret)
                .retrieve()
                .bodyToMono(String.class)
                .block());
    }
}
