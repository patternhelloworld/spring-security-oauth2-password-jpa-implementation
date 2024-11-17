package io.github.patternknife.securityhelper.oauth2.api.config.util;


import io.github.patternknife.securityhelper.oauth2.api.config.security.response.error.exception.KnifeOauth2AuthenticationException;
import io.github.patternknife.securityhelper.oauth2.api.domain.traditionaloauth.bo.BasicTokenResolver;

import jakarta.servlet.http.HttpServletRequest;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
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

        additionalParameters.put(KnifeHttpHeaders.APP_TOKEN, request.getHeader(KnifeHttpHeaders.APP_TOKEN));
        additionalParameters.put(KnifeHttpHeaders.USER_AGENT, request.getHeader(KnifeHttpHeaders.USER_AGENT));
        additionalParameters.put(KnifeHttpHeaders.X_Forwarded_For, request.getHeader(KnifeHttpHeaders.X_Forwarded_For));

        if(!additionalParameters.containsKey("client_id") || StringUtils.isEmpty((String)additionalParameters.get("client_id"))){
            BasicTokenResolver.BasicCredentials basicCredentials = BasicTokenResolver.parse(request.getHeader("Authorization")).orElseThrow(KnifeOauth2AuthenticationException::new);
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

        additionalParameters.add(KnifeHttpHeaders.APP_TOKEN, request.getHeader(KnifeHttpHeaders.APP_TOKEN));
        additionalParameters.add(KnifeHttpHeaders.USER_AGENT, request.getHeader(KnifeHttpHeaders.USER_AGENT));
        additionalParameters.add(KnifeHttpHeaders.X_Forwarded_For, request.getHeader(KnifeHttpHeaders.X_Forwarded_For));

/*        if (!additionalParameters.containsKey("client_id") || StringUtils.isEmpty(additionalParameters.getFirst("client_id"))) {
            BasicTokenResolver.BasicCredentials basicCredentials = BasicTokenResolver.parse(request.getHeader("Authorization")).orElseThrow(KnifeOauth2AuthenticationException::new);
            additionalParameters.add("client_id", basicCredentials.getClientId());
        }*/

        return additionalParameters;
    }

}
