package com.patternknife.securityhelper.oauth2.client.config.logger.common;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.util.ContentCachingRequestWrapper;

import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Map;
import java.util.stream.Collectors;

public class CommonLoggingRequest {

    public String getText() {

        String loggedText = "\n[Before - Thread] : " + Thread.currentThread().getId() + "\n";

        // 1. Request logging
        try {
            loggedText += requestLogging();
        } catch (Exception ex) {
            loggedText += "[Before - Error during the requestLogging] : " + ex.getMessage();
        }

        // 2. Auth
        try {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth != null) {
                loggedText += "[Before - Auth] : " + auth.getName();
            } else {
                loggedText += "[Before - Auth] : " + "null";
            }
        } catch (Exception ex2) {
            loggedText += "[Before - Error during the authGet] : " + ex2.getMessage();
        }

        return loggedText;
    }

/*    public String getPayload(JoinPoint joinPoint) {

        try {
            CodeSignature signature = (CodeSignature) joinPoint.getSignature();
            StringBuilder builder = new StringBuilder();
            for (int i = 0; i < joinPoint.getArgs().length; i++) {
                String parameterName = signature.getParameterNames()[i];
                builder.append(parameterName);
                builder.append(": ");
                if (joinPoint.getArgs()[i] != null) {
                    builder.append(joinPoint.getArgs()[i].toString());
                }
                builder.append(", ");
            }
            return builder.toString();
        } catch (Exception ex) {
            return "[LoggingPayloadFailed] : " + ex.getMessage();
        }

    }*/



    private String paramMapToString(Map<String, String[]> paramMap) {
        return paramMap.entrySet().stream()
                .map(entry -> !checkIfNoLogginParam(entry.getKey()) ? String.format("%s -> (%s)",
                        entry.getKey(), String.join(",", entry.getValue())) : "")
                .collect(Collectors.joining(", "));
    }

    private static final String[] NO_LOGGING_PARAMS = {"image", "aocrImage", "aocrImageZip"};

    private boolean checkIfNoLogginParam(String key) {
        return Arrays.asList(NO_LOGGING_PARAMS).contains(key);
    }


    private String getBodyFromRequest(HttpServletRequest request) throws UnsupportedEncodingException {
        if (request instanceof ContentCachingRequestWrapper) {
            ContentCachingRequestWrapper wrapper = (ContentCachingRequestWrapper) request;
            String requestBody = new String(wrapper.getContentAsByteArray(), request.getCharacterEncoding());
            return requestBody;
        }
        return "Cannot retrieve request body after reading";
    }


    private String requestLogging()  {
        HttpServletRequest request =
                ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();

        Map<String, String[]> paramMap = request.getParameterMap();
        String params = "";
        if (!paramMap.isEmpty()) {
            params = " [" + paramMapToString(paramMap) + "]";
        }


        Enumeration<String> headerNames = request.getHeaderNames();
        StringBuilder headers = new StringBuilder();
        while (headerNames.hasMoreElements()) {
            String headerName = headerNames.nextElement();
            String headerValue = request.getHeader(headerName);
            if(headerName.equals("user-agent") || headerName.equals("authorization")
                    || headerName.equals("content-type")|| headerName.equals("content-length")){
                headers.append(headerName).append(": ").append(headerValue).append("\n");
            }
        }


        String body = "";

        try {
            body = getBodyFromRequest(request);
        }catch (Exception e){
            body = "Exception while body is parsed " + e.getMessage();
        }

        return String.format("[Before - Request] \n%s, %s \n[Before - Request - Headers] \n%s[Before - Request - IP] \n%s\n[Before - Request - Params] \n%s\n[Before - Request - Body] \n%s\n",
                request.getMethod(), request.getRequestURI(), headers.toString(), getRemoteIp(request), params,  body);
    }

    private String getRemoteIp(HttpServletRequest request){

        String ipAddress = request.getHeader("X-Forwarded-For");
        if (ipAddress == null) {
            ipAddress = request.getRemoteAddr();
        }

        return ipAddress;
    }


}
