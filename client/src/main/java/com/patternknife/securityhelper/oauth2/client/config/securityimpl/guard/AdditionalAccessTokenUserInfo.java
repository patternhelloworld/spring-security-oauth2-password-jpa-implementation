package com.patternknife.securityhelper.oauth2.client.config.securityimpl.guard;

import com.patternknife.securityhelper.oauth2.client.domain.admin.entity.Admin;
import com.patternknife.securityhelper.oauth2.client.domain.customer.entity.Customer;
import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;
import java.time.LocalDateTime;

@Getter
@Setter
public class AdditionalAccessTokenUserInfo implements Serializable {

    public enum UserType {
        ADMIN("client_admin"),
        CUSTOMER("client_customer");

        private final String value;

        UserType(String value) {
            this.value = value;
        }

        public String getValue() {
            return value;
        }
    }

    private UserType userType;

    private Long id;
    private String username;
    private String name;

    private LocalDateTime deletedAt;

    public AdditionalAccessTokenUserInfo(Customer customer) {

        this.userType = UserType.CUSTOMER;

        this.id = customer.getId();
        this.username = customer.getIdName();
        this.name = customer.getName();

        this.deletedAt = customer.getDeletedAt();

    }

    public AdditionalAccessTokenUserInfo(Admin admin) {

        this.userType = UserType.ADMIN;

        this.id = admin.getId();
        this.username = admin.getIdName();

        this.deletedAt = admin.getDeletedAt();
    }
}
