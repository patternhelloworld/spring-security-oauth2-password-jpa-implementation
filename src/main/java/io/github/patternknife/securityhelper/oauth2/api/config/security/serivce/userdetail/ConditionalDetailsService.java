package io.github.patternknife.securityhelper.oauth2.api.config.security.serivce.userdetail;


import io.github.patternknife.securityhelper.oauth2.api.config.response.error.exception.auth.KnifeOauth2AuthenticationException;
import io.github.patternknife.securityhelper.oauth2.api.config.security.message.DefaultSecurityUserExceptionMessage;
import io.github.patternknife.securityhelper.oauth2.api.config.response.error.dto.ErrorMessages;
import io.github.patternknife.securityhelper.oauth2.api.config.security.message.ISecurityUserExceptionMessageService;
import lombok.AllArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class ConditionalDetailsService {

    private final UserDetailsServiceFactory userDetailsServiceFactory;
    private final ISecurityUserExceptionMessageService iSecurityUserExceptionMessageService;

    public UserDetails loadUserByUsername(String username, String clientId) throws UsernameNotFoundException, KnifeOauth2AuthenticationException {

        UserDetailsService userDetailsService = userDetailsServiceFactory.getUserDetailsService(clientId);
        if (userDetailsService != null) {
            return userDetailsService.loadUserByUsername(username);
        }
        throw new KnifeOauth2AuthenticationException(ErrorMessages.builder()
                .message("Unable to distinguish whether the user is an Admin or a Customer. (username : " + username + " / client_id: " + clientId + ")")
                .userMessage(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_LOGIN_ERROR))
                .build());

    }
}