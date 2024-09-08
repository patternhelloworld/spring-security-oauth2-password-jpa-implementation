package com.patternknife.securityhelper.oauth2.client.unit.customer;

import io.github.patternknife.securityhelper.oauth2.api.config.security.message.ISecurityUserExceptionMessageService;
import io.github.patternknife.securityhelper.oauth2.api.config.security.serivce.persistence.authorization.OAuth2AuthorizationServiceImpl;
import com.patternknife.securityhelper.oauth2.client.config.response.error.GlobalExceptionHandler;
import com.patternknife.securityhelper.oauth2.client.config.securityimpl.guard.AccessTokenUserInfo;
import com.patternknife.securityhelper.oauth2.client.util.auth.MockAuth;
import com.patternknife.securityhelper.oauth2.client.util.auth.UnitMockAuth;
import com.patternknife.securityhelper.oauth2.client.domain.customer.api.CustomerApi;
import com.patternknife.securityhelper.oauth2.client.domain.customer.dao.CustomerRepository;
import com.patternknife.securityhelper.oauth2.client.domain.customer.dto.CustomerReqDTO;
import com.patternknife.securityhelper.oauth2.client.domain.customer.dto.CustomerResDTO;
import com.patternknife.securityhelper.oauth2.client.domain.customer.entity.Customer;
import com.patternknife.securityhelper.oauth2.client.domain.customer.service.CustomerService;
import org.codehaus.jackson.map.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.core.MethodParameter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.restdocs.RestDocumentationContextProvider;
import org.springframework.restdocs.RestDocumentationExtension;
import org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders;
import org.springframework.restdocs.mockmvc.RestDocumentationResultHandler;
import org.springframework.test.context.event.annotation.BeforeTestMethod;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.filter.CharacterEncodingFilter;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

import static org.hamcrest.CoreMatchers.is;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;
import static org.springframework.restdocs.headers.HeaderDocumentation.headerWithName;
import static org.springframework.restdocs.headers.HeaderDocumentation.requestHeaders;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.documentationConfiguration;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.*;
import static org.springframework.restdocs.payload.PayloadDocumentation.fieldWithPath;
import static org.springframework.restdocs.payload.PayloadDocumentation.relaxedResponseFields;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;


@ExtendWith(RestDocumentationExtension.class)
@ExtendWith(SpringExtension.class)
public class CustomerApiTest {

    /*    @Rule
        public MockitoRule rule = MockitoJUnit.rule();*/
    private CustomerApi customerApi;

    @Mock
    private CustomerService customerService;
    @Mock
    private OAuth2AuthorizationServiceImpl oAuth2AuthorizationServiceImpl;

    @Mock
    private CustomerRepository customerRepository;

    @Mock
    private ISecurityUserExceptionMessageService iSecurityUserExceptionMessageService;


    private MockMvc mockMvc;
    private AccessTokenUserInfo accessTokenUserInfo;

    private RestDocumentationResultHandler document;


    private HandlerMethodArgumentResolver putAuthenticationPrincipal = new HandlerMethodArgumentResolver() {
        @Override
        public boolean supportsParameter(MethodParameter parameter) {
            return parameter.getParameterType().isAssignableFrom(AccessTokenUserInfo.class);
        }

        @Override
        public Object resolveArgument(MethodParameter parameter, ModelAndViewContainer mavContainer,
                                      NativeWebRequest webRequest, WebDataBinderFactory binderFactory) throws Exception {
            return accessTokenUserInfo;
        }
    };


    @BeforeTestMethod
    public void beforeMethod() {
    }

    @BeforeEach
    public void setUp(RestDocumentationContextProvider restDocumentationContextProvider) throws Exception {

        MockitoAnnotations.initMocks(this);


        MockAuth customerUtils = new UnitMockAuth();

        Customer u = customerUtils.mockCustomerObject();

        accessTokenUserInfo = customerUtils.mockAuthenticationPrincipal(u);

        this.document = document(
                "{class-name}/{method-name}",
                preprocessResponse(prettyPrint())
        );

        customerApi = new CustomerApi(customerService, oAuth2AuthorizationServiceImpl, customerRepository);

        mockMvc = MockMvcBuilders.standaloneSetup(customerApi)
                .setControllerAdvice(new GlobalExceptionHandler(iSecurityUserExceptionMessageService))
                .setCustomArgumentResolvers(putAuthenticationPrincipal)
                .apply(documentationConfiguration(restDocumentationContextProvider).uris()
                        .withScheme("https")
                        .withHost("vholic.com")
                        .withPort(443))
                .addFilters(new CharacterEncodingFilter("UTF-8", true))
                .alwaysDo(document)
                .build();

    }



    @Test
    public void updateCustomerTest() throws Exception {

        ObjectMapper objectMapper = new ObjectMapper();

        long customerId = 1L;

        CustomerReqDTO.Update update = new CustomerReqDTO.Update("newemail@example.com", "New Name", "11111", "aaa.com");

        when(customerService.update(anyLong(), any()))
                .thenReturn(new CustomerResDTO.Id(Customer.builder().id(customerId).build()));

        mockMvc.perform(put("/api/v1/customers/" + customerId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(update)))
                .andDo(print()).andExpect(status().isOk())
                .andExpect(jsonPath("id").value(1));
    }



    @Test
    public void testLogoutCustomerSuccess() throws Exception {

        String tokenValue = "sampleToken";

        mockMvc.perform(get("/api/v1/customers/me/logout")
                        .header("Authorization", "Bearer " + tokenValue))
                .andExpect(status().isOk())
                .andExpect(jsonPath("logout", is(true)));

    }


    @Test
    public void deleteMe_200() throws Exception {

        mockMvc.perform(RestDocumentationRequestBuilders.patch("/api/v1/customers/me/delete")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer XXX"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("id").value(1L))
                .andDo(document("{class-name}/{method-name}",
                        preprocessRequest(prettyPrint()),
                        preprocessResponse(prettyPrint()),
                        requestHeaders(
                                headerWithName(HttpHeaders.AUTHORIZATION).description("Bearer XXX")
                        ),
                        relaxedResponseFields(
                                fieldWithPath("id").description("Deleted ID")
                        )));
    }


}