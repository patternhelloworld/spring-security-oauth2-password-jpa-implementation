package com.patternknife.securityhelper.oauth2.mapper;


import com.patternknife.securityhelper.oauth2.domain.customer.dto.CombinedCustomerConditionFilter;
import com.patternknife.securityhelper.oauth2.domain.customer.dto.CustomerResDTO;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.util.List;

@Mapper
public interface CustomerMapper {
    List<CustomerResDTO.OneWithCountsWithAdmin> findByPageFilter(
            @Param("filter") CombinedCustomerConditionFilter filter,
            @Param("limit") int limit,
            @Param("offset") int offset,
            @Param("isMysql") boolean isMysql
    );
    int countByPageFilter(@Param("filter") CombinedCustomerConditionFilter filter);
}