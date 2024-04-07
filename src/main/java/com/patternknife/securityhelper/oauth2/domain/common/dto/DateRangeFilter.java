package com.patternknife.securityhelper.oauth2.domain.common.dto;

import lombok.Data;

@Data
public class DateRangeFilter {
    private String column;
    private String startDate;
    private String endDate;
}
