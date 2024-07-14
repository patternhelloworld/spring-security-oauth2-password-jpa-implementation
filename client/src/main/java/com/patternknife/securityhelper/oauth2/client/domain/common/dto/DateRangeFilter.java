package com.patternknife.securityhelper.oauth2.client.domain.common.dto;

import lombok.Data;

@Data
public class DateRangeFilter {
    private String column;
    private String startDate;
    private String endDate;
}
