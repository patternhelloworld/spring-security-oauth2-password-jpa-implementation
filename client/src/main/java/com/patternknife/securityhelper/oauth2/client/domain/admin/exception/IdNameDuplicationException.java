package com.patternknife.securityhelper.oauth2.client.domain.admin.exception;


import lombok.Getter;

@Getter
public class IdNameDuplicationException extends RuntimeException {

    private String idName;
    private String field;

  public IdNameDuplicationException(String idName) {
        this.field = "idName";
        this.idName = idName;
    }
}
