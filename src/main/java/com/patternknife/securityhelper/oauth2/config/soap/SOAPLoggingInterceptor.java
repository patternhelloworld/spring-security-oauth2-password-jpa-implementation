package com.patternknife.securityhelper.oauth2.config.soap;

import com.patternknife.securityhelper.oauth2.config.logger.module.ResponseSuccessLogConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ws.WebServiceMessage;
import org.springframework.ws.client.WebServiceClientException;
import org.springframework.ws.client.support.interceptor.ClientInterceptor;
import org.springframework.ws.context.MessageContext;
import org.springframework.xml.transform.StringResult;

import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;

public class SOAPLoggingInterceptor implements ClientInterceptor {

    private static final Logger logger = LoggerFactory.getLogger(ResponseSuccessLogConfig.class);

    @Override
    public boolean handleRequest(MessageContext messageContext)  {
        logMessage("Request", messageContext.getRequest());
        return true;
    }

    @Override
    public boolean handleResponse(MessageContext messageContext) {
        logMessage("Response", messageContext.getResponse());
        return true;
    }

    @Override
    public boolean handleFault(MessageContext messageContext) {
        logMessage("Fault", messageContext.getResponse());
        return true;
    }

    private void logMessage(String type, WebServiceMessage message) {
        try {
            StringResult result = new StringResult();
            TransformerFactory.newInstance().newTransformer().transform(message.getPayloadSource(), result);
            logger.error(type + ": " + result.toString());
        } catch (TransformerException e) {
             logger.error("Unable to log SOAP message (" + type + ") : " + e.getMessage());
        }
    }

    @Override
    public void afterCompletion(MessageContext messageContext, Exception e) throws WebServiceClientException {

    }
}