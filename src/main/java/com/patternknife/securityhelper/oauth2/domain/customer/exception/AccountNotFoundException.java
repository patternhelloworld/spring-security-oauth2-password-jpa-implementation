package com.patternknife.securityhelper.oauth2.domain.customer.exception;

import com.patternknife.securityhelper.oauth2.domain.customer.entity.Email;
import lombok.Getter;

@Getter
public class AccountNotFoundException extends RuntimeException {

    private long id;
    private Email email;

    public AccountNotFoundException(long id) {
        this.id = id;
    }

    public AccountNotFoundException(Email email) {
        this.email = email;
    }

}
