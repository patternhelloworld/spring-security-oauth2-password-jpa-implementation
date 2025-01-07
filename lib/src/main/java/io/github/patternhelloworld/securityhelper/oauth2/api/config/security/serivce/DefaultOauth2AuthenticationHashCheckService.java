package io.github.patternhelloworld.securityhelper.oauth2.api.config.security.serivce;


import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.response.error.dto.EasyPlusErrorMessages;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.response.error.exception.EasyPlusOauth2AuthenticationException;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.message.DefaultSecurityUserExceptionMessage;

import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.message.ISecurityUserExceptionMessageService;
import jakarta.annotation.Nullable;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class DefaultOauth2AuthenticationHashCheckService implements IOauth2AuthenticationHashCheckService {

    private final PasswordEncoder passwordEncoder;
    private final ISecurityUserExceptionMessageService iSecurityUserExceptionMessageService;

    public void validateUsernamePassword(String inputPassword, @Nullable UserDetails userDetails){
        if (userDetails == null) {
            throw new EasyPlusOauth2AuthenticationException(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_ID_NO_EXISTS));
        }
        if (!passwordEncoder.matches(inputPassword, userDetails.getPassword())) {
            throw new EasyPlusOauth2AuthenticationException(EasyPlusErrorMessages.builder()
                    .userMessage(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_LOGIN_FAILURE)).message(DefaultSecurityUserExceptionMessage.AUTHENTICATION_WRONG_ID_PASSWORD.getMessage() + " (inputPassword : " + inputPassword + ", input username : " + userDetails.getUsername() + ")").build());
        }
    }

    public void validateClientCredentials(String inputClientSecret, RegisteredClient registeredClient){
        if (registeredClient == null) {
            throw new EasyPlusOauth2AuthenticationException(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_WRONG_CLIENT_ID_SECRET));
        }
        if (!passwordEncoder.matches(inputClientSecret, registeredClient.getClientSecret())) {
            throw new EasyPlusOauth2AuthenticationException(EasyPlusErrorMessages.builder()
                    .userMessage(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_LOGIN_FAILURE)).message(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_WRONG_CLIENT_ID_SECRET) + " (inputClientSecret : " + inputClientSecret+ ")").build());
        }
    }

}
