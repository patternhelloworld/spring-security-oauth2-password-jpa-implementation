package com.patternknife.securityhelper.oauth2.util.auth;

import com.patternknife.securityhelper.oauth2.domain.customer.entity.Customer;
import com.patternknife.securityhelper.oauth2.config.security.principal.AccessTokenUserInfo;

public interface MockAuth {

    /**
     * Mock @AuthenticationPrincipal
     */
    AccessTokenUserInfo mockAuthenticationPrincipal(Customer customer);

    /**
     * Mock Customer
     */
    Customer mockCustomerObject() throws Exception;

    /**
     * Mock AccessToken
     */
    String mockAccessToken(String clientName, String clientPassword, String username, String password) throws Exception;

    /**
     * Mock AccessToken on entity (select from DB)
     */
    String mockAccessTokenOnPersistence(String authUrl, String clientName, String clientPassword, String username, String password) throws Exception;
}
