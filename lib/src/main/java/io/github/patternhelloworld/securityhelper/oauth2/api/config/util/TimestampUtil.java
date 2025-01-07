package io.github.patternhelloworld.securityhelper.oauth2.api.config.util;

import java.util.Date;

public class TimestampUtil {
    public static Date getPayloadTimestamp(){
        return new Date();
    }
}
