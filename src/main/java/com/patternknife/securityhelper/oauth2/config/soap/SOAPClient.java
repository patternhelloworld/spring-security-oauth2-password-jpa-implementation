package com.patternknife.securityhelper.oauth2.config.soap;

import org.springframework.ws.client.core.support.WebServiceGatewaySupport;


public class SOAPClient extends WebServiceGatewaySupport {

    public Object callWebService(String url, Object request){
        return getWebServiceTemplate().marshalSendAndReceive(url, request);
    }
}