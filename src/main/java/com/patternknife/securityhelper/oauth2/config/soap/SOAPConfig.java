package com.patternknife.securityhelper.oauth2.config.soap;

import org.springframework.context.annotation.Configuration;

@Configuration
public class SOAPConfig {
/*    @Bean
    public Jaxb2Marshaller marshaller() {
        Jaxb2Marshaller marshaller = new Jaxb2Marshaller();
        // this is the package name specified in the <generatePackage> specified in
        // pom.xml
        marshaller.setContextPath("com.patternknife.securityhelper.oauth2.microservice.common.coupon");
        return marshaller;
    }

    @Bean
    public SOAPClient soapConnector(Jaxb2Marshaller marshaller) {
        SOAPClient client = new SOAPClient();
        client.setDefaultUri("https://atomtest.donutbook.co.kr:14076/b2ccoupon/b2cservice.aspx?ACTION=CI112_ONLY_ISSUECPN_WITHPAY");
        client.setMarshaller(marshaller);
        client.setUnmarshaller(marshaller);

        client.setInterceptors(new ClientInterceptor[]{new SOAPLoggingInterceptor()});

        return client;
    }*/
  /*  @Bean
    public WebServiceMessageFactory messageFactory()
    {
        SaajSoapMessageFactory messageFactory = new SaajSoapMessageFactory();
        messageFactory.setSoapVersion(SoapVersion.SOAP_12);
        return messageFactory;
    }*/
}
