package io.github.patternhelloworld.securityhelper.oauth2.api.config.util;

import org.springframework.http.HttpHeaders;

public class EasyPlusHttpHeaders extends HttpHeaders {

    public static final String APP_TOKEN = "App-Token";
    public static final String X_Forwarded_For = "X-Forwarded-For";

}
