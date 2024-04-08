package com.patternknife.securityhelper.oauth2.config.security.serivce;

import com.patternknife.securityhelper.oauth2.config.response.error.message.SecurityExceptionMessage;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class Oauth2AuthenticationHashCheckService {

    private final PasswordEncoder passwordEncoder;

    public void validateUsernamePassword(String inputPassword, UserDetails userDetails){
        if (userDetails == null) {
            throw new BadCredentialsException(SecurityExceptionMessage.ID_NO_EXISTS.getMessage());
        }
        if (!passwordEncoder.matches(inputPassword, userDetails.getPassword())) {
            throw new BadCredentialsException(SecurityExceptionMessage.WRONG_ID_PASSWORD.getMessage());
        }
    }

    public Boolean validateClientCredentials(String inputClientSecret, RegisteredClient registeredClient){
        if (registeredClient == null) {
            throw new BadCredentialsException(SecurityExceptionMessage.CLIENT_NO_EXISTS.getMessage());
        }
        if (!passwordEncoder.matches(inputClientSecret, registeredClient.getClientSecret())) {
            throw new BadCredentialsException(SecurityExceptionMessage.WRONG_CLIENT_ID_SECRET.getMessage());
        }else{
            return true;
        }
    }

}
