package com.patternknife.securityhelper.oauth2.client.util.auth;

import io.github.patternknife.securityhelper.oauth2.api.config.security.core.KnifeUserInfo;
import com.patternknife.securityhelper.oauth2.client.domain.customer.entity.Customer;

public class UnitMockAuth extends AbstractMockAuth {



    public UnitMockAuth(){

    }

    @Override
    public KnifeUserInfo mockAuthenticationPrincipal(Customer customer) {
        return super.mockAuthenticationPrincipal(customer);
    }

    @Override
    public Customer mockCustomerObject() {
        return super.mockCustomerObject();
    }

}
