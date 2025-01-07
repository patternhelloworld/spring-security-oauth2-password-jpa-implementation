package io.github.patternhelloworld.securityhelper.oauth2.api.config.util;


import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.response.error.exception.EasyPlusOauth2AuthenticationException;
import io.github.patternhelloworld.securityhelper.oauth2.api.domain.traditionaloauth.bo.BasicTokenResolver;

import jakarta.servlet.http.HttpServletRequest;
import org.apache.commons.lang3.StringUtils;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.HashMap;
import java.util.Map;

public class RequestOAuth2Distiller {


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
            additionalParameters.put(key, value.get(0));
        });

        additionalParameters.put(EasyPlusHttpHeaders.APP_TOKEN, request.getHeader(EasyPlusHttpHeaders.APP_TOKEN));
        additionalParameters.put(EasyPlusHttpHeaders.USER_AGENT, request.getHeader(EasyPlusHttpHeaders.USER_AGENT));
        additionalParameters.put(EasyPlusHttpHeaders.X_Forwarded_For, request.getHeader(EasyPlusHttpHeaders.X_Forwarded_For));

        if(!additionalParameters.containsKey("client_id") || StringUtils.isEmpty((String)additionalParameters.get("client_id"))){
            BasicTokenResolver.BasicCredentials basicCredentials = BasicTokenResolver.parse(request.getHeader("Authorization")).orElseThrow(EasyPlusOauth2AuthenticationException::new);
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

    public static MultiValueMap<String, String> getAuthorizationCodeSecurityAdditionalParameters(HttpServletRequest request) {

        MultiValueMap<String, String> parameters = getParameters(request);
        MultiValueMap<String, String> additionalParameters = new LinkedMultiValueMap<>();

        parameters.forEach((key, value) -> {
            additionalParameters.add(key, value.get(0));
        });

        additionalParameters.add(EasyPlusHttpHeaders.APP_TOKEN, request.getHeader(EasyPlusHttpHeaders.APP_TOKEN));
        additionalParameters.add(EasyPlusHttpHeaders.USER_AGENT, request.getHeader(EasyPlusHttpHeaders.USER_AGENT));
        additionalParameters.add(EasyPlusHttpHeaders.X_Forwarded_For, request.getHeader(EasyPlusHttpHeaders.X_Forwarded_For));

/*        if (!additionalParameters.containsKey("client_id") || StringUtils.isEmpty(additionalParameters.getFirst("client_id"))) {
            BasicTokenResolver.BasicCredentials basicCredentials = BasicTokenResolver.parse(request.getHeader("Authorization")).orElseThrow(EasyPlusOauth2AuthenticationException::new);
            additionalParameters.add("client_id", basicCredentials.getClientId());
        }*/

        return additionalParameters;
    }

}
