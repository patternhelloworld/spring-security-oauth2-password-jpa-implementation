package com.patternknife.securityhelper.oauth2.config.response;

import lombok.Getter;
import lombok.Setter;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.Date;

@Getter
@Setter
public class GlobalSuccessPayload<T> {
    private T data;
    private Date timestamp;
    private String details;

    public GlobalSuccessPayload(T data) {
        this.data = data;
        this.timestamp = TimestampUtil.getPayloadTimestamp();
        this.details = getRequestUri();
    }

    private String getRequestUri() {
        try {
            ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.currentRequestAttributes();
            return attributes.getRequest().getRequestURI();
        } catch (Exception e){
            //e.printStackTrace();
        }
        return null;
    }

}
