package com.patternknife.securityhelper.oauth2.config.response.error.exception.file;

import lombok.AllArgsConstructor;


@AllArgsConstructor
public class FileNotFoundException extends RuntimeException {
    private static final long serialVersionUID = 1L;
    private String message;
}
