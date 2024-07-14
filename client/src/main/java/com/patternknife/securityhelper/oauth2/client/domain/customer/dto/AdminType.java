package com.patternknife.securityhelper.oauth2.client.domain.customer.dto;

import com.patternknife.securityhelper.oauth2.client.domain.customer.entity.Customer;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class AdminType {

    private Boolean isSuperAdmin;
    private Boolean isAdmin;
    private Customer customer;

}
