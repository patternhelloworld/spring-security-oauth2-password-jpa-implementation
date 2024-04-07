package com.patternknife.securityhelper.oauth2.domain.customer.exception;

import com.patternknife.securityhelper.oauth2.domain.customer.entity.Email;
import lombok.Getter;

@Getter
public class EmailDuplicationException extends RuntimeException {

    private Email email;
    private String field;

  public EmailDuplicationException(Email email) {
        this.field = "email";
        this.email = email;
    }
}
