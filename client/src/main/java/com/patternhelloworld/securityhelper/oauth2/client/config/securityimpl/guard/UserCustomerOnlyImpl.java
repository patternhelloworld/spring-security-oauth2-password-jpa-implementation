package com.patternhelloworld.securityhelper.oauth2.client.config.securityimpl.guard;

import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.core.EasyPlusUserInfo;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.message.ISecurityUserExceptionMessageService;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.response.error.exception.EasyPlusOauth2AuthorizationException;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.serivce.persistence.authorization.OAuth2AuthorizationServiceImpl;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.serivce.userdetail.ConditionalDetailsService;
import lombok.RequiredArgsConstructor;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

@Aspect
@Component
@RequiredArgsConstructor
public class UserCustomerOnlyImpl {

    private final OAuth2AuthorizationServiceImpl authorizationService;
    private final ConditionalDetailsService conditionalDetailsService;
    private final ISecurityUserExceptionMessageService iSecurityUserExceptionMessageService;

    @Around("@annotation(com.patternhelloworld.securityhelper.oauth2.client.config.securityimpl.guard.UserCustomerOnly)")
    public Object check(ProceedingJoinPoint joinPoint) throws Throwable {

        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        EasyPlusUserInfo<?> easyPlusUserInfo = AccessTokenUserInfoConverter.from(principal, conditionalDetailsService, authorizationService, iSecurityUserExceptionMessageService);

        if(easyPlusUserInfo != null && ((CustomizedUserInfo) easyPlusUserInfo.getCustomizedUserInfo()).getUserType() != CustomizedUserInfo.UserType.CUSTOMER){
            // Authorization
            throw new EasyPlusOauth2AuthorizationException("ID \"" + easyPlusUserInfo.getUsername() + "\" : Not in Customer Group");
        }

        return joinPoint.proceed();
    }
}