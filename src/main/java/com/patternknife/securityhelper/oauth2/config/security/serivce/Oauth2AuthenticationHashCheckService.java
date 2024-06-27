package com.patternknife.securityhelper.oauth2.config.security.serivce;

import com.patternknife.securityhelper.oauth2.config.logger.dto.ErrorMessages;
import com.patternknife.securityhelper.oauth2.config.response.error.exception.auth.CustomOauth2AuthenticationException;
import com.patternknife.securityhelper.oauth2.config.response.error.message.SecurityUserExceptionMessage;
import jakarta.annotation.Nullable;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class Oauth2AuthenticationHashCheckService {

    private final PasswordEncoder passwordEncoder;

    public void validateUsernamePassword(String inputPassword, @Nullable UserDetails userDetails){
        if (userDetails == null) {
            throw new CustomOauth2AuthenticationException(SecurityUserExceptionMessage.ID_NO_EXISTS.getMessage());
        }
        if (!passwordEncoder.matches(inputPassword, userDetails.getPassword())) {
            throw new CustomOauth2AuthenticationException(ErrorMessages.builder()
                    .userMessage(SecurityUserExceptionMessage.AUTHENTICATION_LOGIN_FAILURE.getMessage()).message(SecurityUserExceptionMessage.WRONG_ID_PASSWORD.getMessage() + " (inputPassword : " + inputPassword + ", input username : " + userDetails.getUsername() + ")").build());
        }
    }

    public void validateClientCredentials(String inputClientSecret, RegisteredClient registeredClient){
        if (registeredClient == null) {
            throw new CustomOauth2AuthenticationException(SecurityUserExceptionMessage.CLIENT_NO_EXISTS.getMessage());
        }
        if (!passwordEncoder.matches(inputClientSecret, registeredClient.getClientSecret())) {
            throw new CustomOauth2AuthenticationException(ErrorMessages.builder()
                    .userMessage(SecurityUserExceptionMessage.AUTHENTICATION_LOGIN_FAILURE.getMessage()).message(SecurityUserExceptionMessage.WRONG_CLIENT_ID_SECRET.getMessage() + " (inputClientSecret : " + inputClientSecret+ ")").build());
        }
    }

}
