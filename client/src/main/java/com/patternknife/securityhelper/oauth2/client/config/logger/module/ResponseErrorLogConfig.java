package com.patternknife.securityhelper.oauth2.client.config.logger.module;

import com.patternknife.securityhelper.oauth2.client.config.response.error.GlobalExceptionHandler;
import com.patternknife.securityhelper.oauth2.client.config.logger.common.CommonLoggingRequest;

import com.patternknife.securityhelper.oauth2.client.config.response.error.dto.CustomErrorResponsePayload;
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


    @AfterReturning(pointcut = ("within(com.patternknife.securityhelper.oauth2.client.config.response.error..*)"),
            returning = "returnValue")
    public void endpointAfterExceptionReturning(JoinPoint p, Object returnValue) {

        String loggedText = "\n[After Throwing Thread] : " + Thread.currentThread().getId() + "\n";

        // 4. Error logging
        try {
            if (p.getTarget().getClass().equals(GlobalExceptionHandler.class)) {

                CustomErrorResponsePayload customErrorResponsePayload = (CustomErrorResponsePayload) ((ResponseEntity) returnValue).getBody();
                loggedText += String.format("[After - Error Response]\n message : %s || \n userMessage : %s || \n cause : %s || \n stackTrace : %s",
                        customErrorResponsePayload != null ? customErrorResponsePayload.getMessage() : "No error message",
                        customErrorResponsePayload != null ? customErrorResponsePayload.getUserMessage() : "No error userMessage",
                        customErrorResponsePayload != null ? customErrorResponsePayload.getCause() : "No error detail cause",
                        customErrorResponsePayload != null ? customErrorResponsePayload.getStackTrace() : "No error detail stack trace");
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