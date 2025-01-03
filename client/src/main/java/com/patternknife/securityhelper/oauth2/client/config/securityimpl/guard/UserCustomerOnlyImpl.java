package com.patternknife.securityhelper.oauth2.client.config.securityimpl.guard;

import com.patternknife.securityhelper.oauth2.client.config.response.error.exception.auth.CustomAuthGuardException;
import io.github.patternknife.securityhelper.oauth2.api.config.security.serivce.persistence.authorization.OAuth2AuthorizationServiceImpl;
import io.github.patternknife.securityhelper.oauth2.api.config.security.serivce.userdetail.ConditionalDetailsService;
import lombok.RequiredArgsConstructor;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionAuthenticatedPrincipal;
import org.springframework.stereotype.Component;

@Aspect
@Component
@RequiredArgsConstructor
public class UserCustomerOnlyImpl {

    private final OAuth2AuthorizationServiceImpl authorizationService;
    private final ConditionalDetailsService conditionalDetailsService;

    @Around("@annotation(com.patternknife.securityhelper.oauth2.client.config.securityimpl.guard.UserCustomerOnly)")
    public Object check(ProceedingJoinPoint joinPoint) throws Throwable {

        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();

        String userName =((OAuth2IntrospectionAuthenticatedPrincipal)principal).getUsername();
        String clientId  =((OAuth2IntrospectionAuthenticatedPrincipal)principal).getClientId();
        String appToken =  ((OAuth2IntrospectionAuthenticatedPrincipal)principal).getAttribute("App-Token");


        OAuth2Authorization oAuth2Authorization = authorizationService.findByUserNameAndClientIdAndAppToken(userName, clientId, appToken);

        UserDetails userDetails = conditionalDetailsService.loadUserByUsername(userName, clientId);

        AccessTokenUserInfo accessTokenUserInfo = ((AccessTokenUserInfo)userDetails);


        if(accessTokenUserInfo != null && (accessTokenUserInfo.getAdditionalAccessTokenUserInfo().getUserType() != AdditionalAccessTokenUserInfo.UserType.CUSTOMER)){
            throw new CustomAuthGuardException("ID \"" + accessTokenUserInfo.getUsername() + "\" : Not in Customer Group");
        }

        return joinPoint.proceed();
    }
}