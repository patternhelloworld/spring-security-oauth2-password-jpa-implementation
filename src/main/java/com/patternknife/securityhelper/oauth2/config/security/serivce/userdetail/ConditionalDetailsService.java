package com.patternknife.securityhelper.oauth2.config.security.serivce.userdetail;

import com.patternknife.securityhelper.oauth2.config.logger.dto.ErrorMessages;
import com.patternknife.securityhelper.oauth2.config.response.error.message.SecurityExceptionMessage;
import com.patternknife.securityhelper.oauth2.config.response.error.exception.auth.UnauthenticatedException;
import com.patternknife.securityhelper.oauth2.config.security.principal.AdditionalAccessTokenUserInfo;
import lombok.AllArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class ConditionalDetailsService {

    private AdminDetailsService adminDetailsService;
    private CustomerDetailsService customerDetailsService;

    public UserDetails loadUserByUsername(String username, String clientId){
        if(clientId.equals(AdditionalAccessTokenUserInfo.UserType.CUSTOMER.getValue())){
            return customerDetailsService.loadUserByUsername(username);
        }else if(clientId.equals(AdditionalAccessTokenUserInfo.UserType.ADMIN.getValue())){
            return adminDetailsService.loadUserByUsername(username);
        }else {
            throw new UnauthenticatedException(ErrorMessages.builder()
                    .message("Unable to distinguish whether the user is an Admin or a Customer. (client_id: " + clientId + ")")
                    .userMessage(SecurityExceptionMessage.AUTHENTICATION_ERROR.getMessage())
                    .build());
        }
    }
}
