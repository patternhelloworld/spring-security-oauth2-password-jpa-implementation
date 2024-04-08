package com.patternknife.securityhelper.oauth2.config.response;

import org.springframework.core.MethodParameter;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyAdvice;


/*
    Use when wanting to arbitrarily change the Response Payload.
    Use when other methods have been explored and do not work.
* */
@ControllerAdvice
public class SpecificResponseHandler implements ResponseBodyAdvice<Object> {

    @Override
    public boolean supports(MethodParameter returnType, Class converterType) {
        // You can add your conditions here
        // Return true if you want to exute beceforeBodyWrite method for this response
        // Return false if you don't want to apply this advice to the response
        return true;
    }

    @Override
    public Object beforeBodyWrite(Object body, MethodParameter returnType, MediaType selectedContentType,
                                  Class selectedConverterType, ServerHttpRequest request, ServerHttpResponse response) {

        // /oauth2/token
        if(body instanceof OAuth2AccessToken && ((ServletServerHttpResponse) response).getServletResponse().getStatus() == HttpStatus.OK.value()) {
            return new GlobalSuccessPayload<>(body);
        }else{
            return body;
        }
        //return body;
    }
}
