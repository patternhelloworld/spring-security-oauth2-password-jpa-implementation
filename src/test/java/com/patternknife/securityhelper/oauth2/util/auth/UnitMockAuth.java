package com.patternknife.securityhelper.oauth2.util.auth;

import com.patternknife.securityhelper.oauth2.domain.customer.entity.Customer;
import com.patternknife.securityhelper.oauth2.config.security.principal.AccessTokenUserInfo;

public class UnitMockAuth extends AbstractMockAuth {



    public UnitMockAuth(){

    }

    @Override
    public AccessTokenUserInfo mockAuthenticationPrincipal(Customer customer) {
        return super.mockAuthenticationPrincipal(customer);
    }

    @Override
    public Customer mockCustomerObject() {
        return super.mockCustomerObject();
    }

}
