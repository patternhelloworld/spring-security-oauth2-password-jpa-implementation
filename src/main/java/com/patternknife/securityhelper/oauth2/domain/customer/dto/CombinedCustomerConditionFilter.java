package com.patternknife.securityhelper.oauth2.domain.customer.dto;

import com.patternknife.securityhelper.oauth2.domain.common.dto.DateRangeFilter;
import com.patternknife.securityhelper.oauth2.domain.common.dto.SorterValueFilter;
import lombok.Data;

@Data
public class CombinedCustomerConditionFilter {
    private DateRangeFilter dateRangeFilter;
    private CustomerSearchFilter customerSearchFilter;
    private SorterValueFilter sorterValueFilter;
}
