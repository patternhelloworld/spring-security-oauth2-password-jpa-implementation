package com.patternknife.securityhelper.oauth2.config.logger.module;

import com.patternknife.securityhelper.oauth2.config.CustomHttpHeaders;
import com.patternknife.securityhelper.oauth2.config.response.error.CustomExceptionUtils;
import com.patternknife.securityhelper.oauth2.config.security.principal.AccessTokenUserInfo;
import com.patternknife.securityhelper.oauth2.config.security.principal.AdditionalAccessTokenUserInfo;
import com.patternknife.securityhelper.oauth2.domain.customerlog.dao.CustomerLogRepository;
import com.patternknife.securityhelper.oauth2.domain.customerlog.entity.CustomerLog;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.springframework.dao.DataIntegrityViolationException;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;


import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;


/*
*   마케팅 목적으로 특정 시간 대에서 접속한 사용자 수를 확인하기 위함
*   CustomerLog 테이블의 구조는 특정 시간 이 아닌 분, 초 로도 확장이 가능 (그렇게 할 가능성은 없지만...)
*   모두 저장하는 것은 DB에 무리가 가기 때문에, 앱이 하기 API 를 호출할 때, 시간 단위로 사용자를 기록.
* */
@RequiredArgsConstructor
@Aspect
@Component
public class CustomerDBLogConfig {


    private final CustomerLogRepository customerLogRepository;

    // @Before("execution(* com.patternknife.securityhelper.oauth2.domain.banner.api.BannerApi.getBanners(..))")
    @Before("execution(* com.patternknife.securityhelper.oauth2.domain.push.api.PushApi.createPushToken(..))")
    public void beforeCreatePushToken() {

        HttpServletRequest request =
                ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();

        String appTokenValue = request.getHeader(CustomHttpHeaders.APP_TOKEN);
        Authentication currentAuth = SecurityContextHolder.getContext().getAuthentication();

        if (currentAuth != null && currentAuth.getPrincipal() instanceof AccessTokenUserInfo) {

            AccessTokenUserInfo userInfo = (AccessTokenUserInfo) currentAuth.getPrincipal();
            AdditionalAccessTokenUserInfo additionalAccessTokenUserInfo = userInfo.getAdditionalAccessTokenUserInfo();
            AdditionalAccessTokenUserInfo.UserType userType = userInfo.getAdditionalAccessTokenUserInfo().getUserType();

            if (userType == AdditionalAccessTokenUserInfo.UserType.CUSTOMER) {

                LocalDateTime timeWithZeroMinutesAndSeconds = LocalDateTime.now().truncatedTo(ChronoUnit.HOURS);

                CustomerLog customerLog = customerLogRepository.findByTimeValueAndTimeMeasurementAndCustomerId(timeWithZeroMinutesAndSeconds, CustomerLog.TimeMeasurement.H, additionalAccessTokenUserInfo.getId()).orElse(null);
                if (customerLog != null) {
                    return;
                } else {
                    customerLog = new CustomerLog();
                }

                customerLog.setAppToken(appTokenValue);
                // 지금은 그냥 디폴트를 사용한다.
                customerLog.setBehavior(0);
                // [중요] 시간 단위를 유니크 로 잡아서 동일한 시간 내에 사용자 접속 기록을 중복 삽입하지 않는다.

                customerLog.setTimeValue(timeWithZeroMinutesAndSeconds);
                customerLog.setTimeMeasurement(CustomerLog.TimeMeasurement.H);
                customerLog.setCustomerId(additionalAccessTokenUserInfo.getId());

                try {
                    customerLogRepository.save(customerLog);
                } catch (DataIntegrityViolationException e) {
                    // 동시성 문제로 customerLogRepository.findByTimeValueAndTimeMeasurementAndCustomerId 에서 거르지 못했다면, 여기서 무시한다.
                    CustomExceptionUtils.createNonStoppableErrorMessage("Custoemr Log 디버깅 : " + e.getMessage());
                }

            } else {
                // CUSTOMER 로그 목적 용 이므로 별다른 어뷰징을 확인하지 않는다.
            }

        }
    }

}