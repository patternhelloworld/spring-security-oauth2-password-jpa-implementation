package com.patternknife.securityhelper.oauth2.client.config.securityimpl.guard;

import io.github.patternknife.securityhelper.oauth2.api.config.security.core.KnifeUserInfo;
import io.github.patternknife.securityhelper.oauth2.api.config.security.message.ISecurityUserExceptionMessageService;
import io.github.patternknife.securityhelper.oauth2.api.config.security.response.error.exception.KnifeOauth2AuthorizationException;
import io.github.patternknife.securityhelper.oauth2.api.config.security.serivce.persistence.authorization.OAuth2AuthorizationServiceImpl;
import io.github.patternknife.securityhelper.oauth2.api.config.security.serivce.userdetail.ConditionalDetailsService;
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

    @Around("@annotation(com.patternknife.securityhelper.oauth2.client.config.securityimpl.guard.UserCustomerOnly)")
    public Object check(ProceedingJoinPoint joinPoint) throws Throwable {

        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        KnifeUserInfo<?> knifeUserInfo = AccessTokenUserInfoConverter.from(principal, conditionalDetailsService, authorizationService, iSecurityUserExceptionMessageService);

        if(knifeUserInfo != null && ((CustomizedUserInfo) knifeUserInfo.getCustomizedUserInfo()).getUserType() != CustomizedUserInfo.UserType.CUSTOMER){
            // Authorization
            throw new KnifeOauth2AuthorizationException("ID \"" + knifeUserInfo.getUsername() + "\" : Not in Customer Group");
        }

        return joinPoint.proceed();
    }
}