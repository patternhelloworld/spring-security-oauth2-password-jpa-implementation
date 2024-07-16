package io.github.patternknife.securityhelper.oauth2.api.config.security;

import org.springframework.http.HttpHeaders;

public class KnifeHttpHeaders extends HttpHeaders {

    public static final String APP_TOKEN = "App-Token";
    public static final String X_Forwarded_For = "X-Forwarded-For";

}
