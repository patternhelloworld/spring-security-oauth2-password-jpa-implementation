package com.patternknife.securityhelper.oauth2.config.logger.module;

import com.patternknife.securityhelper.oauth2.config.logger.common.CommonLoggingRequest;
import com.patternknife.securityhelper.oauth2.config.logger.dto.ErrorDetails;
import com.patternknife.securityhelper.oauth2.config.response.error.GlobalExceptionHandler;
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


    @AfterReturning(pointcut = ("within(com.patternknife.securityhelper.oauth2.config.response.error..*)"),
            returning = "returnValue")
    public void endpointAfterExceptionReturning(JoinPoint p, Object returnValue) {

        String loggedText = "\n[After Throwing Thread] : " + Thread.currentThread().getId() + "\n";

        // 4. Error logging
        try {
            if (p.getTarget().getClass().equals(GlobalExceptionHandler.class)) {

                ErrorDetails errorDetails = (ErrorDetails) ((ResponseEntity) returnValue).getBody();
                loggedText += String.format("[After - Error Response]\n message : %s || \n userMessage : %s || \n cause : %s || \n stackTrace : %s",
                        errorDetails != null ? errorDetails.getMessage() : "No error detail message",
                        errorDetails != null ? errorDetails.getUserMessage() : "No error detail auth message",
                        errorDetails != null ? errorDetails.getCause() : "No error detail cause",
                        errorDetails != null ? errorDetails.getStackTrace() : "No error detail stack trace");
            }
        } catch (Exception ex4) {

            loggedText += "\n[Error during the errorLogging] : " + ex4.getMessage();
        }

        // 5. 발생한 객체
        try {
            loggedText += "\n[Location] : " + p.getTarget().getClass().getSimpleName() + " " + p.getSignature().getName();
        } catch (Exception ex5) {
            loggedText += "\n[Error during the finalStage] : " + ex5.getMessage();
        }

        CommonLoggingRequest commonLoggingRequest = new CommonLoggingRequest();

        logger.error(commonLoggingRequest.getText() + loggedText + "|||\n");
    }


}