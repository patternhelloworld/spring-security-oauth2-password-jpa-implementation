package com.patternhelloworld.securityhelper.oauth2.client.config.response.error.exception.auth;

import org.springframework.security.core.userdetails.UsernameNotFoundException;


public class UserDeletedException extends UsernameNotFoundException {
    public UserDeletedException(String message) {
        super(message);
    }
}