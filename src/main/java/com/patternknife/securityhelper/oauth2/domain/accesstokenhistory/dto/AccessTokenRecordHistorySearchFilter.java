package com.patternknife.securityhelper.oauth2.domain.accesstokenhistory.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@JsonIgnoreProperties(ignoreUnknown = true)
public class AccessTokenRecordHistorySearchFilter {
    private String userName;
    private String userAgent;
}
