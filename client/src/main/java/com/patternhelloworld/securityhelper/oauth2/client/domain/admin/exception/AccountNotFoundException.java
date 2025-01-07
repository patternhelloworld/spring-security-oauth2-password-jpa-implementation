package com.patternhelloworld.securityhelper.oauth2.client.domain.admin.exception;

import lombok.Getter;

@Getter
public class AccountNotFoundException extends RuntimeException {

    private long id;
    private String idName;

    public AccountNotFoundException(long id) {
        this.id = id;
    }

    public AccountNotFoundException(String idName) {
        this.idName = idName;
    }

}
