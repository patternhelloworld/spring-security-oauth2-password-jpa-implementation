package com.patternhelloworld.securityhelper.oauth2.client.domain.admin.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@JsonIgnoreProperties(ignoreUnknown = true)
public class AdminSearchFilter {

    private String idName;

}
