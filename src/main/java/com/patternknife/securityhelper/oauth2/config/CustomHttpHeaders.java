package com.patternknife.securityhelper.oauth2.config;

import org.springframework.http.HttpHeaders;

public class CustomHttpHeaders extends HttpHeaders {

    public static final String APP_TOKEN = "App-Token";
    public static final String X_Forwarded_For = "X-Forwarded-For";

}
