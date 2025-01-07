package com.patternhelloworld.securityhelper.oauth2.client.util.auth;

import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.core.EasyPlusUserInfo;
import com.patternhelloworld.securityhelper.oauth2.client.domain.customer.entity.Customer;

public class UnitMockAuth extends AbstractMockAuth {



    public UnitMockAuth(){

    }

    @Override
    public EasyPlusUserInfo mockAuthenticationPrincipal(Customer customer) {
        return super.mockAuthenticationPrincipal(customer);
    }

    @Override
    public Customer mockCustomerObject() {
        return super.mockCustomerObject();
    }

}
