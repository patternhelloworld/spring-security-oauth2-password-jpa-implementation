package com.patternknife.securityhelper.oauth2.domain.customer.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;

@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class CustomerSearchFilter {

    private Long id;

    private String email;
    private String idName;
    private String name;

    private Long maxId;

}
