package com.patternhelloworld.securityhelper.oauth2.client;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import javax.annotation.PostConstruct;
import java.util.TimeZone;


@SpringBootApplication(scanBasePackages =  {"com.patternhelloworld.securityhelper.oauth2.client", "io.github.patternhelloworld.securityhelper.oauth2.api"})
public class SpringSecurityOauth2PasswordJpaImplApplication {

    @PostConstruct
    void init() {
        TimeZone.setDefault(TimeZone.getTimeZone("Asia/Seoul"));
    }

    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityOauth2PasswordJpaImplApplication.class, args);
    }

}
