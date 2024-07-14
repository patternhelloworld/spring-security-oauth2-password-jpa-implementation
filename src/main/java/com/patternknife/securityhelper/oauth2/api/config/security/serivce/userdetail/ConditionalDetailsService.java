package com.patternknife.securityhelper.oauth2.api.config.security.serivce.userdetail;


import com.patternknife.securityhelper.oauth2.api.config.response.error.exception.auth.KnifeOauth2AuthenticationException;
import com.patternknife.securityhelper.oauth2.api.config.response.error.message.SecurityUserExceptionMessage;
import com.patternknife.securityhelper.oauth2.api.config.response.error.dto.ErrorMessages;
import lombok.AllArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class ConditionalDetailsService {

    private final UserDetailsServiceFactory userDetailsServiceFactory;

    public UserDetails loadUserByUsername(String username, String clientId) throws UsernameNotFoundException, KnifeOauth2AuthenticationException {

        UserDetailsService userDetailsService = userDetailsServiceFactory.getUserDetailsService(clientId);
        if (userDetailsService != null) {
            return userDetailsService.loadUserByUsername(username);
        }
        throw new KnifeOauth2AuthenticationException(ErrorMessages.builder()
                .message("Unable to distinguish whether the user is an Admin or a Customer. (username : " + username + " / client_id: " + clientId + ")")
                .userMessage(SecurityUserExceptionMessage.AUTHENTICATION_LOGIN_ERROR.getMessage())
                .build());

    }
}
