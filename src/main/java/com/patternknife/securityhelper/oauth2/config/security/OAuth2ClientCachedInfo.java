package com.patternknife.securityhelper.oauth2.config.security;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/*
 [Important] If you change the value here, it must match with the oauth_client_details in the DB
 As for the scope value, using both read and write as the default for all is recommended.
*/

public enum OAuth2ClientCachedInfo {

    RESOURCE_IDS("client_resource", null),

    ADMIN_CLIENT_ID("client_admin", new HashSet<>(Arrays.asList("read", "write"))),
    CUSTOMER_CLIENT_ID("client_customer", new HashSet<>(Arrays.asList("read", "write")));

    private final String value;
    private final Set<String> scope;

    OAuth2ClientCachedInfo(String value, Set<String> scope) {
        this.value = value;
        this.scope = scope;
    }

    public String getValue() {
        return value;
    }

    public Set<String> getScope() {
        return scope;
    }

    public static Set<String> getScopeByValue(String value) {
        for (OAuth2ClientCachedInfo constItem : OAuth2ClientCachedInfo.values()) {
            if (constItem.getValue().equals(value)) {
                return constItem.getScope();
            }
        }
        return null;
    }
}

