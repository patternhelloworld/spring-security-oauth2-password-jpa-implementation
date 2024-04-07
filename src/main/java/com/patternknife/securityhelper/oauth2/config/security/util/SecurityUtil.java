package com.patternknife.securityhelper.oauth2.config.security.util;

import com.patternknife.securityhelper.oauth2.config.CustomHttpHeaders;
import com.patternknife.securityhelper.oauth2.config.response.error.exception.auth.UnauthorizedException;
import com.patternknife.securityhelper.oauth2.config.security.principal.AccessTokenUserInfo;
import com.patternknife.securityhelper.oauth2.config.security.principal.AdditionalAccessTokenUserInfo;
import com.patternknife.securityhelper.oauth2.domain.traditionaloauth.bo.BasicTokenResolver;
import com.patternknife.securityhelper.oauth2.util.CustomUtils;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

public class SecurityUtil {

    public static AdditionalAccessTokenUserInfo.UserType getAccessTokenUserType(Principal principal) {
        if (principal instanceof AccessTokenUserInfo) {
            if (((AccessTokenUserInfo) principal).getAdditionalAccessTokenUserInfo().getUserType().equals(AdditionalAccessTokenUserInfo.UserType.CUSTOMER)) {
                return AdditionalAccessTokenUserInfo.UserType.CUSTOMER;
            } else if (((AccessTokenUserInfo) principal).getAdditionalAccessTokenUserInfo().getUserType().equals(AdditionalAccessTokenUserInfo.UserType.ADMIN)) {
                return AdditionalAccessTokenUserInfo.UserType.ADMIN;
            }else{
                return null;
            }
        }
        return null;
    }

    public static AdditionalAccessTokenUserInfo.UserType getAccessTokenUserType(){

        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();

        if (principal instanceof AccessTokenUserInfo) {
            if (((AccessTokenUserInfo) principal).getAdditionalAccessTokenUserInfo().getUserType().equals(AdditionalAccessTokenUserInfo.UserType.CUSTOMER)) {
                return AdditionalAccessTokenUserInfo.UserType.CUSTOMER;
            } else if (((AccessTokenUserInfo) principal).getAdditionalAccessTokenUserInfo().getUserType().equals(AdditionalAccessTokenUserInfo.UserType.ADMIN)) {
                return AdditionalAccessTokenUserInfo.UserType.ADMIN;
            }else{
                return null;
            }
        }

        return null;
    }

    public static AccessTokenUserInfo getAccessTokenUser(){

        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();

        if (principal instanceof AccessTokenUserInfo) {
            return ((AccessTokenUserInfo) principal);
        }

        return null;
    }


    /*
    *
    *   The following 8 values will be passed through the whole authorization process to be parts of "Oauth2Authorization".
    *
            "password" -> ""
            "grant_type" -> "password"
            "App-Token" -> ""
            "User-Agent" -> "PostmanRuntime/7.37.0"
            "X-Forwarded-For" -> ""
            "otp_value" -> "555555"
            "username" -> "",
            "client_id" -> ""
    *
    * */
    public static Map<String, Object> getTokenUsingSecurityAdditionalParameters(HttpServletRequest request){

        MultiValueMap<String, String> parameters = getParameters(request);


        Map<String, Object> additionalParameters = new HashMap<>();

        parameters.forEach((key, value) -> {
            if (//!OAuth2ParameterNames.GRANT_TYPE.equals(key) &&
                    //   !OAuth2ParameterNames.CLIENT_ID.equals(key) &&
                    !OAuth2ParameterNames.CODE.equals(key) &&
                    !OAuth2ParameterNames.CLIENT_SECRET.equals(key)) {
                additionalParameters.put(key, value.get(0));
            }
        });

        additionalParameters.put(CustomHttpHeaders.APP_TOKEN, request.getHeader(CustomHttpHeaders.APP_TOKEN));
        additionalParameters.put(CustomHttpHeaders.USER_AGENT, request.getHeader(CustomHttpHeaders.USER_AGENT));
        additionalParameters.put(CustomHttpHeaders.X_Forwarded_For, request.getHeader(CustomHttpHeaders.X_Forwarded_For));

        if(!additionalParameters.containsKey("client_id") || CustomUtils.isEmpty((String)additionalParameters.get("client_id"))){
            BasicTokenResolver.BasicCredentials basicCredentials = BasicTokenResolver.parse(request.getHeader("Authorization")).orElseThrow(UnauthorizedException::new);
            additionalParameters.put("client_id", basicCredentials.getClientId());
        }

        return additionalParameters;
    }


    private static MultiValueMap<String, String> getParameters(HttpServletRequest request) {
        Map<String, String[]> parameterMap = request.getParameterMap();
        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>(parameterMap.size());
        parameterMap.forEach((key, values) -> {
            if (values.length > 0) {
                for (String value : values) {
                    parameters.add(key, value);
                }
            }
        });
        return parameters;
    }


    /*
*
*   The following 8 values will be passed through the whole authorization process to be parts of "Oauth2Authorization".
*
        "password" -> ""
        "grant_type" -> "password"
        "App-Token" -> ""
        "User-Agent" -> "PostmanRuntime/7.37.0"
        "X-Forwarded-For" -> ""
        "otp_value" -> "555555"
        "username" -> "",
        "client_id" -> ""
*
* */
    public static Map<String, Object> getTokenUsingSecurityAdditionalParametersSocial(HttpServletRequest request, String username){

        MultiValueMap<String, String> parameters = getParameters(request);

        Map<String, Object> additionalParameters = new HashMap<>();

        parameters.forEach((key, value) -> {
            if (//!OAuth2ParameterNames.GRANT_TYPE.equals(key) &&
                //   !OAuth2ParameterNames.CLIENT_ID.equals(key) &&
                    !OAuth2ParameterNames.CODE.equals(key) &&
                            !OAuth2ParameterNames.CLIENT_SECRET.equals(key)) {
                additionalParameters.put(key, value.get(0));
            }
        });

        additionalParameters.put(CustomHttpHeaders.APP_TOKEN, request.getHeader(CustomHttpHeaders.APP_TOKEN));
        additionalParameters.put(CustomHttpHeaders.USER_AGENT, request.getHeader(CustomHttpHeaders.USER_AGENT));
        additionalParameters.put(CustomHttpHeaders.X_Forwarded_For, request.getHeader(CustomHttpHeaders.X_Forwarded_For));
        additionalParameters.put("client_id", AdditionalAccessTokenUserInfo.UserType.CUSTOMER.getValue());
        additionalParameters.put("grant_type", "password");
        additionalParameters.put("username", username);

        return additionalParameters;
    }



}
