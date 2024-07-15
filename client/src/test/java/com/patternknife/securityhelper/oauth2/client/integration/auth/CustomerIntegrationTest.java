package com.patternknife.securityhelper.oauth2.client.integration.auth;


import com.patternknife.securityhelper.oauth2.api.config.response.error.message.SecurityUserExceptionMessage;
import com.patternknife.securityhelper.oauth2.api.config.security.KnifeHttpHeaders;
import jakarta.xml.bind.DatatypeConverter;
import lombok.SneakyThrows;
import org.codehaus.jackson.map.ObjectMapper;
import org.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.restdocs.AutoConfigureRestDocs;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.restdocs.RestDocumentationContextProvider;
import org.springframework.restdocs.RestDocumentationExtension;
import org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders;
import org.springframework.restdocs.mockmvc.RestDocumentationResultHandler;
import org.springframework.restdocs.operation.OperationRequest;
import org.springframework.restdocs.operation.OperationRequestFactory;
import org.springframework.restdocs.operation.OperationResponse;
import org.springframework.restdocs.operation.OperationResponseFactory;
import org.springframework.restdocs.operation.preprocess.OperationPreprocessor;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.context.WebApplicationContext;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.restdocs.headers.HeaderDocumentation.headerWithName;
import static org.springframework.restdocs.headers.HeaderDocumentation.requestHeaders;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.*;
import static org.springframework.restdocs.payload.PayloadDocumentation.fieldWithPath;
import static org.springframework.restdocs.payload.PayloadDocumentation.relaxedResponseFields;
import static org.springframework.restdocs.request.RequestDocumentation.formParameters;
import static org.springframework.restdocs.request.RequestDocumentation.parameterWithName;
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
@AutoConfigureRestDocs(outputDir = "target/generated-snippets",uriScheme = "https", uriHost = "vholic.com", uriPort = 8300)
public class CustomerIntegrationTest {

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
    public void setUp(RestDocumentationContextProvider restDocumentationContextProvide) throws UnsupportedEncodingException {

        basicHeader = "Basic " + DatatypeConverter.printBase64Binary((appUserClientId + ":" + appUserClientSecret).getBytes("UTF-8"));

    }

    @Test
    public void test_SameAppTokensUseSameAccessToken_EXPOSED() throws Exception {

        /*
        *    Access Token (APP-TOKEN : APPTOKENAAA)
        * */

        MvcResult result = mockMvc.perform(RestDocumentationRequestBuilders.post("/api/v1/traditional-oauth/token")
                        .header(HttpHeaders.AUTHORIZATION, basicHeader)
                        .header(KnifeHttpHeaders.APP_TOKEN, "APPTOKENAAA")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "password")
                        .param("username", testUserName)
                        .param("password", testUserPassword))
               .andExpect(status().isOk())
                .andDo(document( "{class-name}/{method-name}/oauth-access-token",
                        preprocessRequest(new AccessTokenMaskingPreprocessor()),
                        preprocessResponse(new AccessTokenMaskingPreprocessor(), prettyPrint()),
                        requestHeaders(
                                headerWithName(HttpHeaders.AUTHORIZATION).description("Connect the received client_id and client_secret with ':', use the base64 function, and write Basic at the beginning. ex) Basic base64(client_id:client_secret)"),
                                headerWithName(KnifeHttpHeaders.APP_TOKEN).optional().description("Not having a value does not mean you cannot log in, but cases without an App-Token value share the same access_token. Please include it as a required value according to the device-specific session policy.")
                        ),
                        formParameters(
                                parameterWithName("grant_type").description("Uses the password method among Oauth2 grant_types. Please write password."),
                                parameterWithName("username").description("This is the user's email address."),
                                parameterWithName("password").description("This is the user's password.")
                        )))
                .andReturn();


        String responseString = result.getResponse().getContentAsString();
        JSONObject jsonResponse = new JSONObject(responseString);
        String refreshToken = jsonResponse.getString("refresh_token");
        String accessTokenForAppToken1 = jsonResponse.getString("access_token");


        /*
         *    Access Token (APP-TOKEN : X)
         * */

        result = mockMvc.perform(RestDocumentationRequestBuilders.post("/api/v1/traditional-oauth/token")
                        .header(HttpHeaders.AUTHORIZATION, basicHeader)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "password")
                        .param("username", testUserName)
                        .param("password", testUserPassword))
                .andExpect(status().isOk())
                .andDo(document( "{class-name}/{method-name}/oauth-access-token",
                        preprocessRequest(new AccessTokenMaskingPreprocessor()),
                        preprocessResponse(new AccessTokenMaskingPreprocessor(), prettyPrint()),
                        requestHeaders(
                                headerWithName(HttpHeaders.AUTHORIZATION).description("Connect the received client_id and client_secret with ':', use the base64 function, and write Basic at the beginning. ex) Basic base64(client_id:client_secret)"),
                                headerWithName(KnifeHttpHeaders.APP_TOKEN).optional().description("Not having a value does not mean you cannot log in, but cases without an App-Token value share the same access_token. Please include it as a required value according to the device-specific session policy.")
                        ),
                        formParameters(
                                parameterWithName("grant_type").description("Uses the password method among Oauth2 grant_types. Please write password."),
                                parameterWithName("username").description("This is the user's email address."),
                                parameterWithName("password").description("This is the user's password.")
                        )))
                .andReturn();


        responseString = result.getResponse().getContentAsString();
        jsonResponse = new JSONObject(responseString);
        refreshToken = jsonResponse.getString("refresh_token");
        String accessToken = jsonResponse.getString("access_token");

        /*
         *    Access Token (APP-TOKEN : APPTOKENAAA)
         * */
        result = mockMvc.perform(RestDocumentationRequestBuilders.post("/api/v1/traditional-oauth/token")
                        .header(HttpHeaders.AUTHORIZATION, basicHeader)
                        .header(KnifeHttpHeaders.APP_TOKEN, "APPTOKENAAA2")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "password")
                        .param("username", testUserName)
                        .param("password", testUserPassword))
                .andExpect(status().isOk()).andReturn();


        responseString = result.getResponse().getContentAsString();
        jsonResponse = new JSONObject(responseString);
        refreshToken = jsonResponse.getString("refresh_token");
        accessToken = jsonResponse.getString("access_token");



        /*
         *    Refresh Token (APP-TOKEN : APPTOKENAAA2)
         * */
        result = mockMvc.perform(RestDocumentationRequestBuilders.post("/api/v1/traditional-oauth/token")
                        .header(HttpHeaders.AUTHORIZATION, basicHeader)
                        .header(KnifeHttpHeaders.APP_TOKEN, "APPTOKENAAA2")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "refresh_token")
                        .param("refresh_token", refreshToken))
                .andExpect(status().isOk())
                .andDo(document( "{class-name}/{method-name}/oauth-refresh-token",
                        preprocessRequest(new RefreshTokenMaskingPreprocessor()),
                        preprocessResponse(new RefreshTokenMaskingPreprocessor(), prettyPrint()),
                        requestHeaders(
                                headerWithName(HttpHeaders.AUTHORIZATION).description("Connect the received client_id and client_secret with ':', use the base64 function, and write Basic at the beginning. ex) Basic base64(client_id:client_secret)"),
                                headerWithName(KnifeHttpHeaders.APP_TOKEN).optional().description("Not having a value does not mean you cannot log in, but cases without an App-Token value share the same access_token. Please include it as a required value according to the device-specific session policy.")
                        ),
                        formParameters(
                                parameterWithName("grant_type").description("Uses the refresh_token method among Oauth2 grant_types. Please write refresh_token."),
                                parameterWithName("refresh_token").description("XXX")
                        )))
                .andReturn();

        responseString = result.getResponse().getContentAsString();
        jsonResponse = new JSONObject(responseString);
        String accessToken2 = jsonResponse.getString("access_token");

        if(accessToken2.equals(accessToken)){
            assertNotEquals("The new access_token issued with a refresh_token should not be the same value as the existing access_token.", accessToken2, accessToken);
        }else{
            assertTrue(true, "Success");
        }

        /*
         *      LOGOUT
         *
         *      : ONLY APPTOKENAAA2 SHOULD BE LOGGED OUT
         * */
        mockMvc.perform(RestDocumentationRequestBuilders.get("/api/v1/customers/me/logout")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken2))
                .andExpect(status().isOk())
                .andDo(document( "{class-name}/{method-name}/oauth-customer-logout",
                        requestHeaders(
                                headerWithName(HttpHeaders.AUTHORIZATION).description("Bearer XXX")
                        ),relaxedResponseFields(
                                fieldWithPath("logout").description("If true, logout is successful on the backend, if false, it fails. However, ignore this message and, considering UX, delete the token on the client side and move to the login screen.")

                        )));


        /*
         *    Access Token (APP-TOKEN : APPTOKENAAA)
         * */

        result = mockMvc.perform(RestDocumentationRequestBuilders.post("/api/v1/traditional-oauth/token")
                        .header(HttpHeaders.AUTHORIZATION, basicHeader)
                        .header(KnifeHttpHeaders.APP_TOKEN, "APPTOKENAAA")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "password")
                        .param("username", testUserName)
                        .param("password", testUserPassword))
                .andExpect(status().isOk())
                .andDo(document( "{class-name}/{method-name}/oauth-access-token",
                        preprocessRequest(new AccessTokenMaskingPreprocessor()),
                        preprocessResponse(new AccessTokenMaskingPreprocessor(), prettyPrint()),
                        requestHeaders(
                                headerWithName(HttpHeaders.AUTHORIZATION).description("Connect the received client_id and client_secret with ':', use the base64 function, and write Basic at the beginning. ex) Basic base64(client_id:client_secret)"),
                                headerWithName(KnifeHttpHeaders.APP_TOKEN).optional().description("Not having a value does not mean you cannot log in, but cases without an App-Token value share the same access_token. Please include it as a required value according to the device-specific session policy.")
                        ),
                        formParameters(
                                parameterWithName("grant_type").description("Uses the password method among Oauth2 grant_types. Please write password."),
                                parameterWithName("username").description("This is the user's email address."),
                                parameterWithName("password").description("This is the user's password.")
                        )))
                .andReturn();


        responseString = result.getResponse().getContentAsString();
        jsonResponse = new JSONObject(responseString);
        refreshToken = jsonResponse.getString("refresh_token");
        String finalAccessTokenForAppToken1 = jsonResponse.getString("access_token");

        // Check the availability of the access token for APPTOKENAAA
        mockMvc.perform(get("/api/v1/customers/me")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + finalAccessTokenForAppToken1))
                .andDo(print())
                .andExpect(status().isOk());

        if(!accessTokenForAppToken1.equals(finalAccessTokenForAppToken1)){
            assertEquals("The Access Token corresponding to the initial app token was different.", accessTokenForAppToken1, finalAccessTokenForAppToken1);
        }else{
            assertTrue(true, "Success");
        }
    }

    @Test
    public void test_SameAppTokensUseSameAccessToken_ORIGINAL() throws Exception {

        MvcResult result = mockMvc.perform(RestDocumentationRequestBuilders.post("/oauth2/token")
                        .header(HttpHeaders.AUTHORIZATION, basicHeader)
                        .header(KnifeHttpHeaders.APP_TOKEN, "APPTOKENAAA")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "password")
                        .param("username", testUserName)
                        .param("password", testUserPassword))
                .andExpect(status().isOk())
                .andDo(document( "{class-name}/{method-name}/oauth-access-token",
                        preprocessRequest(new AccessTokenMaskingPreprocessor()),
                        preprocessResponse(new AccessTokenMaskingPreprocessor(), prettyPrint()),
                        requestHeaders(
                                headerWithName(HttpHeaders.AUTHORIZATION).description("Connect the received client_id and client_secret with ':', use the base64 function, and write Basic at the beginning. ex) Basic base64(client_id:client_secret)"),
                                headerWithName(KnifeHttpHeaders.APP_TOKEN).optional().description("Not having a value does not mean you cannot log in, but cases without an App-Token value share the same access_token. Please include it as a required value according to the device-specific session policy.")
                        ),
                        formParameters(
                                parameterWithName("grant_type").description("Uses the password method among Oauth2 grant_types. Please write password."),
                                parameterWithName("username").description("This is the user's email address."),
                                parameterWithName("password").description("This is the user's password.")
                        )))
                .andReturn();


        String responseString = result.getResponse().getContentAsString();
        JSONObject jsonResponse = new JSONObject(responseString);
        String refreshToken = jsonResponse.getString("refresh_token");
        String accessTokenForAppToken1 = jsonResponse.getString("access_token");


        result = mockMvc.perform(RestDocumentationRequestBuilders.post("/oauth2/token")
                        .header(HttpHeaders.AUTHORIZATION, basicHeader)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "password")
                        .param("username", testUserName)
                        .param("password", testUserPassword))
                .andExpect(status().isOk())
                .andDo(document( "{class-name}/{method-name}/oauth-access-token",
                        preprocessRequest(new AccessTokenMaskingPreprocessor()),
                        preprocessResponse(new AccessTokenMaskingPreprocessor(), prettyPrint()),
                        requestHeaders(
                                headerWithName(HttpHeaders.AUTHORIZATION).description("Connect the received client_id and client_secret with ':', use the base64 function, and write Basic at the beginning. ex) Basic base64(client_id:client_secret)"),
                                headerWithName(KnifeHttpHeaders.APP_TOKEN).optional().description("Not having a value does not mean you cannot log in, but cases without an App-Token value share the same access_token. Please include it as a required value according to the device-specific session policy.")
                        ),
                        formParameters(
                                parameterWithName("grant_type").description("Uses the password method among Oauth2 grant_types. Please write password."),
                                parameterWithName("username").description("This is the user's email address."),
                                parameterWithName("password").description("This is the user's password.")
                        )))
                .andReturn();


        responseString = result.getResponse().getContentAsString();
        jsonResponse = new JSONObject(responseString);
        refreshToken = jsonResponse.getString("refresh_token");
        String accessToken = jsonResponse.getString("access_token");


        result = mockMvc.perform(RestDocumentationRequestBuilders.post("/oauth2/token")
                        .header(HttpHeaders.AUTHORIZATION, basicHeader)
                        .header(KnifeHttpHeaders.APP_TOKEN, "APPTOKENAAA2")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "password")
                        .param("username", testUserName)
                        .param("password", testUserPassword))
                .andExpect(status().isOk()).andReturn();


        responseString = result.getResponse().getContentAsString();
        jsonResponse = new JSONObject(responseString);
        refreshToken = jsonResponse.getString("refresh_token");
        accessToken = jsonResponse.getString("access_token");



        result = mockMvc.perform(RestDocumentationRequestBuilders.post("/oauth2/token")
                        .header(HttpHeaders.AUTHORIZATION, basicHeader)
                        .header(KnifeHttpHeaders.APP_TOKEN, "APPTOKENAAA2")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "refresh_token")
                        .param("refresh_token", refreshToken))
                .andExpect(status().isOk())
                .andDo(document( "{class-name}/{method-name}/oauth-refresh-token",
                        preprocessRequest(new RefreshTokenMaskingPreprocessor()),
                        preprocessResponse(new RefreshTokenMaskingPreprocessor(), prettyPrint()),
                        requestHeaders(
                                headerWithName(HttpHeaders.AUTHORIZATION).description("Connect the received client_id and client_secret with ':', use the base64 function, and write Basic at the beginning. ex) Basic base64(client_id:client_secret)"),
                                headerWithName(KnifeHttpHeaders.APP_TOKEN).optional().description("Not having a value does not mean you cannot log in, but cases without an App-Token value share the same access_token. Please include it as a required value according to the device-specific session policy.")
                        ),
                        formParameters(
                                parameterWithName("grant_type").description("Uses the refresh_token method among Oauth2 grant_types. Please write refresh_token."),
                                parameterWithName("refresh_token").description("XXX")
                        )))
                .andReturn();

        responseString = result.getResponse().getContentAsString();
        jsonResponse = new JSONObject(responseString);
        String accessToken2 = jsonResponse.getString("access_token");


        if(accessToken2.equals(accessToken)){
            assertNotEquals("The new access_token issued with a refresh_token should not be the same value as the existing access_token.", accessToken2, accessToken);
        }else{
            assertTrue(true, "Success");
        }

        mockMvc.perform(RestDocumentationRequestBuilders.get("/api/v1/customers/me/logout")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken2))
                .andExpect(status().isOk())
                .andDo(document( "{class-name}/{method-name}/oauth-customer-logout",
                        requestHeaders(
                                headerWithName(HttpHeaders.AUTHORIZATION).description("Bearer XXX")
                        ),relaxedResponseFields(
                                fieldWithPath("logout").description("If true, logout is successful on the backend, if false, it fails. However, ignore this message and, considering UX, delete the token on the client side and move to the login screen.")
                        )));



        result = mockMvc.perform(RestDocumentationRequestBuilders.post("/oauth2/token")
                        .header(HttpHeaders.AUTHORIZATION, basicHeader)
                        .header(KnifeHttpHeaders.APP_TOKEN, "APPTOKENAAA")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "password")
                        .param("username", testUserName)
                        .param("password", testUserPassword))
                .andExpect(status().isOk())
                .andDo(document( "{class-name}/{method-name}/oauth-access-token",
                        preprocessRequest(new AccessTokenMaskingPreprocessor()),
                        preprocessResponse(new AccessTokenMaskingPreprocessor(), prettyPrint()),
                        requestHeaders(
                                headerWithName(HttpHeaders.AUTHORIZATION).description("Connect the received client_id and client_secret with ':', use the base64 function, and write Basic at the beginning. ex) Basic base64(client_id:client_secret)"),
                                headerWithName(KnifeHttpHeaders.APP_TOKEN).optional().description("Not having a value does not mean you cannot log in, but cases without an App-Token value share the same access_token. Please include it as a required value according to the device-specific session policy.")
                        ),
                        formParameters(
                                parameterWithName("grant_type").description("Uses the password method among Oauth2 grant_types. Please write password."),
                                parameterWithName("username").description("This is the user's email address."),
                                parameterWithName("password").description("This is the user's password.")
                        )))
                .andReturn();


        responseString = result.getResponse().getContentAsString();
        jsonResponse = new JSONObject(responseString);
        refreshToken = jsonResponse.getString("refresh_token");
        String finalAccessTokenForAppToken1 = jsonResponse.getString("access_token");


        // Check the availability of the access token for APPTOKENAAA
        mockMvc.perform(get("/api/v1/customers/me")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + finalAccessTokenForAppToken1))
                .andDo(print())
                .andExpect(status().isOk());

        if(!accessTokenForAppToken1.equals(finalAccessTokenForAppToken1)){
            assertEquals("The Access Token corresponding to the initial app token was different.", accessTokenForAppToken1, finalAccessTokenForAppToken1);
        }else{
            assertTrue(true, "Success");
        }
    }

    @Test
    public void testLoginWithInvalidCredentials_ORIGINAL() throws Exception {


        MvcResult result = mockMvc.perform(RestDocumentationRequestBuilders.post("/oauth2/token")
                        .header(HttpHeaders.AUTHORIZATION, basicHeader)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "password")
                        .param("username", testUserName + "wrongcredential")
                        .param("password", testUserPassword))
                .andExpect(status().isUnauthorized()) // 401
                .andDo(document( "{class-name}/{method-name}/oauth-access-token",
                        preprocessRequest(new AccessTokenMaskingPreprocessor()),
                        preprocessResponse(new AccessTokenMaskingPreprocessor(), prettyPrint()),
                        requestHeaders(
                                headerWithName(HttpHeaders.AUTHORIZATION).description("Connect the received client_id and client_secret with ':', use the base64 function, and write Basic at the beginning. ex) Basic base64(client_id:client_secret)"),
                                headerWithName(KnifeHttpHeaders.APP_TOKEN).optional().description("Not having a value does not mean you cannot log in, but cases without an App-Token value share the same access_token. Please include it as a required value according to the device-specific session policy.")
                        ),
                        formParameters(
                                parameterWithName("grant_type").description("Uses the password method among Oauth2 grant_types. Please write password."),
                                parameterWithName("username").description("This is the user's email address."),
                                parameterWithName("password").description("This is the user's password.")
                        )))
                .andReturn();


        String responseString = result.getResponse().getContentAsString();
        JSONObject jsonResponse = new JSONObject(responseString);
        String userMessage = jsonResponse.getString("userMessage");

        assertEquals(userMessage, SecurityUserExceptionMessage.AUTHENTICATION_LOGIN_FAILURE.getMessage());



        result = mockMvc.perform(RestDocumentationRequestBuilders.post("/oauth2/token")
                        .header(HttpHeaders.AUTHORIZATION, "Basic " + DatatypeConverter.printBase64Binary((appUserClientId + "wrongcred:" + appUserClientSecret).getBytes("UTF-8")))
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "password")
                        .param("username", testUserName)
                        .param("password", testUserPassword))
                .andExpect(status().isUnauthorized()) // 401
                .andDo(document( "{class-name}/{method-name}/oauth-access-token",
                        preprocessRequest(new AccessTokenMaskingPreprocessor()),
                        preprocessResponse(new AccessTokenMaskingPreprocessor(), prettyPrint()),
                        requestHeaders(
                                headerWithName(HttpHeaders.AUTHORIZATION).description("Connect the received client_id and client_secret with ':', use the base64 function, and write Basic at the beginning. ex) Basic base64(client_id:client_secret)"),
                                headerWithName(KnifeHttpHeaders.APP_TOKEN).optional().description("Not having a value does not mean you cannot log in, but cases without an App-Token value share the same access_token. Please include it as a required value according to the device-specific session policy.")
                        ),
                        formParameters(
                                parameterWithName("grant_type").description("Uses the password method among Oauth2 grant_types. Please write password."),
                                parameterWithName("username").description("This is the user's email address."),
                                parameterWithName("password").description("This is the user's password.")
                        )))
                .andReturn();


        responseString = result.getResponse().getContentAsString();
        jsonResponse = new JSONObject(responseString);
        userMessage = jsonResponse.getString("userMessage");

        assertEquals(userMessage, SecurityUserExceptionMessage.WRONG_CLIENT_ID_SECRET.getMessage());
    }


    @Test
    public void testLoginWithInvalidCredentials_EXPOSE() throws Exception {

        MvcResult result = mockMvc.perform(RestDocumentationRequestBuilders.post("/api/v1/traditional-oauth/token")
                        .header(HttpHeaders.AUTHORIZATION, basicHeader)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "password")
                        .param("username", testUserName + "wrongcredential")
                        .param("password", testUserPassword))
                .andExpect(status().isUnauthorized()) // 401
                .andDo(document( "{class-name}/{method-name}/oauth-access-token",
                        preprocessRequest(new AccessTokenMaskingPreprocessor()),
                        preprocessResponse(new AccessTokenMaskingPreprocessor(), prettyPrint()),
                        requestHeaders(
                                headerWithName(HttpHeaders.AUTHORIZATION).description("Connect the received client_id and client_secret with ':', use the base64 function, and write Basic at the beginning. ex) Basic base64(client_id:client_secret)"),
                                headerWithName(KnifeHttpHeaders.APP_TOKEN).optional().description("Not having a value does not mean you cannot log in, but cases without an App-Token value share the same access_token. Please include it as a required value according to the device-specific session policy.")
                        ),
                        formParameters(
                                parameterWithName("grant_type").description("Uses the password method among Oauth2 grant_types. Please write password."),
                                parameterWithName("username").description("This is the user's email address."),
                                parameterWithName("password").description("This is the user's password.")
                        )))
                .andReturn();


        String responseString = result.getResponse().getContentAsString();
        JSONObject jsonResponse = new JSONObject(responseString);
        String userMessage = jsonResponse.getString("userMessage");

        assertEquals(userMessage, SecurityUserExceptionMessage.AUTHENTICATION_LOGIN_FAILURE.getMessage());



        result = mockMvc.perform(RestDocumentationRequestBuilders.post("/api/v1/traditional-oauth/token")
                        .header(HttpHeaders.AUTHORIZATION, "Basic " + DatatypeConverter.printBase64Binary((appUserClientId + "wrongcred:" + appUserClientSecret).getBytes("UTF-8")))
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "password")
                        .param("username", testUserName)
                        .param("password", testUserPassword))
                .andExpect(status().isUnauthorized()) // 401
                .andDo(document( "{class-name}/{method-name}/oauth-access-token",
                        preprocessRequest(new AccessTokenMaskingPreprocessor()),
                        preprocessResponse(new AccessTokenMaskingPreprocessor(), prettyPrint()),
                        requestHeaders(
                                headerWithName(HttpHeaders.AUTHORIZATION).description("Connect the received client_id and client_secret with ':', use the base64 function, and write Basic at the beginning. ex) Basic base64(client_id:client_secret)"),
                                headerWithName(KnifeHttpHeaders.APP_TOKEN).optional().description("Not having a value does not mean you cannot log in, but cases without an App-Token value share the same access_token. Please include it as a required value according to the device-specific session policy.")
                        ),
                        formParameters(
                                parameterWithName("grant_type").description("Uses the password method among Oauth2 grant_types. Please write password."),
                                parameterWithName("username").description("This is the user's email address."),
                                parameterWithName("password").description("This is the user's password.")
                        )))
                .andReturn();


        responseString = result.getResponse().getContentAsString();
        jsonResponse = new JSONObject(responseString);
        userMessage = jsonResponse.getString("userMessage");

        assertEquals(userMessage, SecurityUserExceptionMessage.WRONG_CLIENT_ID_SECRET.getMessage());
    }



    private static class AccessTokenMaskingPreprocessor implements OperationPreprocessor {

        @Override
        public OperationRequest preprocess(OperationRequest request) {


            HttpHeaders httpHeaders = new HttpHeaders();
            httpHeaders.putAll(request.getHeaders());
            httpHeaders.set("Authorization", "Basic XXX");


/*           String originalContent = new String(request.getContent(), StandardCharsets.UTF_8);
            originalContent += "&"
            JsonObject jsonObject = JsonParser.parseString(originalContent).getAsJsonObject();
            jsonObject.addProperty("grant_type", "XXX");*/
            byte[] updatedContent = "grant_type=password&username=XXX&password=XXX".getBytes(StandardCharsets.UTF_8);



            return new OperationRequestFactory().create(request.getUri(),
                    request.getMethod(), updatedContent, httpHeaders,
                    request.getParts());
        }

        @SneakyThrows
        @Override
        public OperationResponse preprocess(OperationResponse response) {

            byte[] modifiedContent = response.getContent();

            ObjectMapper objectMapper = new ObjectMapper();
            Map<String, Object> contentMap = objectMapper.readValue(response.getContent(), Map.class);
            if (contentMap.containsKey("data")) {
                Map<String, Object> dataMap = (Map<String, Object>) contentMap.get("data");
                if (dataMap.containsKey("access_token")) {
                    dataMap.put("access_token", "XXX");
                }

                if (dataMap.containsKey("refresh_token")) {
                    dataMap.put("refresh_token", "XXX");
                }

                contentMap.put("data", dataMap);

                modifiedContent = objectMapper.writeValueAsBytes(contentMap);
            }


            HttpHeaders httpHeaders = new HttpHeaders();
            httpHeaders.putAll(response.getHeaders());

            return new OperationResponseFactory().create(response.getStatus(), httpHeaders, modifiedContent);
        }

    }



    private static class RefreshTokenMaskingPreprocessor implements OperationPreprocessor {

        @Override
        public OperationRequest preprocess(OperationRequest request) {

            HttpHeaders httpHeaders = new HttpHeaders();
            httpHeaders.putAll(request.getHeaders());
            httpHeaders.set("Authorization", "Basic XXX");

 /*           String originalContent = new String(request.getContent(), StandardCharsets.UTF_8);
            JsonObject jsonObject = JsonParser.parseString(originalContent).getAsJsonObject();
            jsonObject.addProperty("grant_type", "XXX");
            byte[] updatedContent = jsonObject.toString().getBytes(StandardCharsets.UTF_8);
*/
            byte[] updatedContent = "grant_type=refresh_token&refresh_token=XXX".getBytes(StandardCharsets.UTF_8);

            return new OperationRequestFactory().create(request.getUri(),
                    request.getMethod(), updatedContent, httpHeaders,
                    request.getParts());
        }

        @SneakyThrows
        @Override
        public OperationResponse preprocess(OperationResponse response) {

            byte[] modifiedContent = response.getContent();

            ObjectMapper objectMapper = new ObjectMapper();
            Map<String, Object> contentMap = objectMapper.readValue(response.getContent(), Map.class);
            if (contentMap.containsKey("data")) {
                Map<String, Object> dataMap = (Map<String, Object>) contentMap.get("data");
                if (dataMap.containsKey("access_token")) {
                    dataMap.put("access_token", "XXX");
                }

                if (dataMap.containsKey("refresh_token")) {
                    dataMap.put("refresh_token", "XXX");
                }

                contentMap.put("data", dataMap);

                modifiedContent = objectMapper.writeValueAsBytes(contentMap);
            }



            HttpHeaders httpHeaders = new HttpHeaders();
            httpHeaders.putAll(response.getHeaders());

            return new OperationResponseFactory().create(response.getStatus(), httpHeaders, modifiedContent);
        }

    }




}