package com.patternhelloworld.securityhelper.oauth2.client.integration.auth;


import jakarta.xml.bind.DatatypeConverter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.restdocs.AutoConfigureRestDocs;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.restdocs.RestDocumentationContextProvider;
import org.springframework.restdocs.RestDocumentationExtension;
import org.springframework.restdocs.mockmvc.RestDocumentationResultHandler;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.context.WebApplicationContext;

import java.io.UnsupportedEncodingException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;


/*
*    Functions ending with
*       "ORIGINAL" : '/oauth2/token'
*       "EXPOSED" : '/api/v1/traditional-oauth/token'
* */
@ExtendWith(RestDocumentationExtension.class)
@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
@AutoConfigureRestDocs(outputDir = "target/generated-snippets",uriScheme = "http", uriHost = "localhost", uriPort = 8370)
public class AuthorizationIntegrationTest {

    private static final Logger logger = LoggerFactory.getLogger(AuthorizationIntegrationTest.class);


    @Autowired
    private MockMvc mockMvc;


    @Value("${app.oauth2.appUser.clientId}")
    private String appUserClientId;
    @Value("${app.oauth2.appUser.clientSecret}")
    private String appUserClientSecret;

    @Value("${app.test.auth.customer.username}")
    private String testUserName;
    @Value("${app.test.auth.customer.password}")
    private String testUserPassword;


    private RestDocumentationResultHandler document;

    private String basicHeader;

    @Autowired
    private WebApplicationContext webApplicationContext;


    @BeforeEach
    public void setUp(RestDocumentationContextProvider restDocumentationContextProvider) throws UnsupportedEncodingException {

        basicHeader = "Basic " + DatatypeConverter.printBase64Binary((appUserClientId + ":" + appUserClientSecret).getBytes("UTF-8"));

    }
    @Test
    public void testAuthorizationCodeMissingException() throws Exception {
        MvcResult result = mockMvc.perform(get("/oauth2/authorize?response_type=code&client_id=client_customer&state=xxx&scope=read&redirect_uri=http://localhost:8081/callback1"))
                .andExpect(status().is2xxSuccessful())
                .andDo(print())
                .andReturn();
        assertEquals("/login", result.getResponse().getForwardedUrl());
/*        String responseContent = result.getResponse().getContentAsString(StandardCharsets.UTF_8);
        assertTrue(responseContent.contains("AUTHENTICATION_AUTHORIZATION_CODE_MISSING"),
                "The response should contain the error code 'AUTHENTICATION_AUTHORIZATION_CODE_MISSING'.");*/
    }

}