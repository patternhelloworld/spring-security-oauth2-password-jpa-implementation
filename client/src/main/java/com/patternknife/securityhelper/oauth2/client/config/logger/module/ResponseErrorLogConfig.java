package com.patternknife.securityhelper.oauth2.client.config.logger.module;

import com.patternknife.securityhelper.oauth2.client.config.response.error.GlobalExceptionHandler;
import com.patternknife.securityhelper.oauth2.client.config.logger.common.CommonLoggingRequest;


import io.github.patternknife.securityhelper.oauth2.api.config.security.response.error.dto.SecurityKnifeErrorResponsePayload;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.AfterReturning;
import org.aspectj.lang.annotation.Aspect;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;


@Aspect
@Component
public class ResponseErrorLogConfig {

    private static final Logger logger = LoggerFactory.getLogger(ResponseErrorLogConfig.class);


    @AfterReturning(pointcut = ("within(com.patternknife.securityhelper.oauth2.client.config.response.error..*) || within(io.github.patternknife.securityhelper.oauth2.api.config.security.response.error.handler..*)"),
            returning = "returnValue")
    public void endpointAfterExceptionReturning(JoinPoint p, Object returnValue) {

        String loggedText = "\n[After Throwing Thread] : " + Thread.currentThread().getId() + "\n";

        // 4. Error logging
        try {
            if (p.getTarget().getClass().equals(GlobalExceptionHandler.class)) {

                SecurityKnifeErrorResponsePayload errorResponsePayload = (SecurityKnifeErrorResponsePayload) ((ResponseEntity) returnValue).getBody();
                loggedText += String.format("[After - Error Response]\n message : %s || \n userMessage : %s || \n cause : %s || \n stackTrace : %s",
                        errorResponsePayload != null ? errorResponsePayload.getMessage() : "No error message",
                        errorResponsePayload != null ? errorResponsePayload.getUserMessage() : "No error userMessage",
                        errorResponsePayload != null ? errorResponsePayload.getCause() : "No error detail cause",
                        errorResponsePayload != null ? errorResponsePayload.getStackTrace() : "No error detail stack trace");
            }
        } catch (Exception ex4) {

            loggedText += "\n[Error during the errorLogging] : " + ex4.getMessage();
        }

        try {
            loggedText += "\n[Location] : " + p.getTarget().getClass().getSimpleName() + " " + p.getSignature().getName();
        } catch (Exception ex5) {
            loggedText += "\n[Error during the finalStage] : " + ex5.getMessage();
        }

        CommonLoggingRequest commonLoggingRequest = new CommonLoggingRequest();

        logger.error(commonLoggingRequest.getText() + loggedText + "|||\n");
    }


}