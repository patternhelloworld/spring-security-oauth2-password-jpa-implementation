package com.patternknife.securityhelper.oauth2.config.response;

import java.util.Date;

public class TimestampUtil {
    public static Date getPayloadTimestamp(){
        return new Date();
    }
}
