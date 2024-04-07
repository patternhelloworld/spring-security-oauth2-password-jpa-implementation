package com.patternknife.securityhelper.oauth2.unit.customer;

import com.patternknife.securityhelper.oauth2.config.CustomHttpHeaders;
import com.patternknife.securityhelper.oauth2.config.response.error.GlobalExceptionHandler;
import com.patternknife.securityhelper.oauth2.config.security.serivce.OAuth2AuthorizationServiceImpl;
import com.patternknife.securityhelper.oauth2.config.security.principal.AccessTokenUserInfo;
import com.patternknife.securityhelper.oauth2.domain.customer.api.CustomerApi;
import com.patternknife.securityhelper.oauth2.domain.customer.dao.CustomerRepository;
import com.patternknife.securityhelper.oauth2.domain.customer.dto.CustomerReqDTO;
import com.patternknife.securityhelper.oauth2.domain.customer.dto.CustomerResDTO;
import com.patternknife.securityhelper.oauth2.domain.customer.entity.Customer;
import com.patternknife.securityhelper.oauth2.domain.customer.service.CustomerService;
import com.patternknife.securityhelper.oauth2.domain.interestedtreatmentpart.dao.InterestedTreatmentPartService;
import com.patternknife.securityhelper.oauth2.domain.interestedtreatmentpart.dto.InterestedTreatmentPartReqDTO;
import com.patternknife.securityhelper.oauth2.domain.interestedtreatmentpart.dto.InterestedTreatmentPartResDTO;
import com.patternknife.securityhelper.oauth2.domain.interestedtreatmentpart.entity.InterestedTreatmentPart;
import com.patternknife.securityhelper.oauth2.domain.push.service.PushAppTokenService;
import com.patternknife.securityhelper.oauth2.domain.socialoauth.dto.SpringSecuritySocialOauthDTO;
import com.patternknife.securityhelper.oauth2.util.TestUtil;
import com.patternknife.securityhelper.oauth2.util.auth.MockAuth;
import com.patternknife.securityhelper.oauth2.util.auth.UnitMockAuth;
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

import java.sql.Timestamp;
import java.time.LocalDate;
import java.time.LocalDateTime;

import static org.hamcrest.CoreMatchers.is;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.when;
import static org.springframework.restdocs.headers.HeaderDocumentation.headerWithName;
import static org.springframework.restdocs.headers.HeaderDocumentation.requestHeaders;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.documentationConfiguration;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.*;
import static org.springframework.restdocs.payload.PayloadDocumentation.*;
import static org.springframework.restdocs.request.RequestDocumentation.parameterWithName;
import static org.springframework.restdocs.request.RequestDocumentation.queryParameters;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
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
    private OAuth2AuthorizationServiceImpl OAuth2AuthorizationServiceImpl;
    @Mock
    private InterestedTreatmentPartService interestedTreatmentPartService;
    @Mock
    private CustomerRepository customerRepository;
    @Mock
    private PushAppTokenService pushAppTokenService;


    private MockMvc mockMvc;
    private AccessTokenUserInfo accessTokenUserInfo;

    private RestDocumentationResultHandler document;

    // Controller에 @AuthenticationPrincipal을 Injection 한다.
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

        // 기본 권한만 부여된 사용자로 시작한다.
        MockAuth customerUtils = new UnitMockAuth();

        Customer u = customerUtils.mockCustomerObject();
        // putAuthenticationPrincipal 에 Inject
        accessTokenUserInfo = customerUtils.mockAuthenticationPrincipal(u);

        this.document = document(
                "{class-name}/{method-name}",
                preprocessResponse(prettyPrint())
        );

        customerApi = new CustomerApi(customerService, OAuth2AuthorizationServiceImpl, interestedTreatmentPartService, customerRepository, pushAppTokenService);

        mockMvc = MockMvcBuilders.standaloneSetup(customerApi)
                .setControllerAdvice(new GlobalExceptionHandler())
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
    public void getCustomerMeWithResources_조회_200() throws Exception {

        String customerIdName = "cicd@test.com";

        //given : anyString() 자리에 "cicd@test.com" 이 들어가면 통과하지만, 임의의 다른 String "test2@test.com" 을 넣으면 실패한다.
        // 이는 실제 CustomerController 에 해당 API 에 debug 포인트를 설정하면 알 수 있다.
        when(customerService.findCustomerOneWithResources(anyLong())).thenReturn(
                new CustomerResDTO.OneWithResources(1L, customerIdName, "tester", "aa", "010-555-3333", 500L, 33L, 22L, null, null));

        // when, then
        mockMvc.perform(get("/api/v1/customers/me/resources").contentType(MediaType.APPLICATION_JSON)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer XXX"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("data.idName").value(customerIdName))
                .andDo(document("{class-name}/{method-name}",
                        preprocessResponse(prettyPrint()),
                        requestHeaders(
                                headerWithName(HttpHeaders.AUTHORIZATION).description("인증을 통해 받은 access_token 앞에 Bearer 를 붙여서 전송. ex) Bearer XXX")
                        )));


    }


    @Test
    public void getCustomerMeInterestedTreatmentParts_조회_200() throws Exception {

        int upperPart = 1;

        //given : anyString() 자리에 "cicd@test.com" 이 들어가면 통과하지만, 임의의 다른 String "test2@test.com" 을 넣으면 실패한다.
        // 이는 실제 CustomerController 에 해당 API 에 debug 포인트를 설정하면 알 수 있다.
        when(customerService.findCustomerOneWithInterestedTreatmentParts(anyString())).thenReturn(
                new CustomerResDTO.OneWithInterestedTreatmentParts(1L, 1L, upperPart, 0, 2, null, null));

        // then
        mockMvc.perform(get("/api/v1/customers/me/interested-treatment-parts").contentType(MediaType.APPLICATION_JSON)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer XXX"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("data.upperPart").value(upperPart))
                .andDo(document("{class-name}/{method-name}",
                        preprocessResponse(prettyPrint()),
                        requestHeaders(
                                headerWithName(HttpHeaders.AUTHORIZATION).description("인증을 통해 받은 access_token 앞에 Bearer 를 붙여서 전송. ex) Bearer XXX")
                        )));


    }


    @Test
    public void updateCustomerInterestedTreatmentPart_200() throws Exception {

        // Given
        Long customerId = 1L;
        InterestedTreatmentPartResDTO.IdCustomerId given = new InterestedTreatmentPartResDTO.IdCustomerId(
                InterestedTreatmentPart.builder()
                        .id(1L)
                        .customer(Customer.builder().id(customerId).build())
                        .interestSetDate(LocalDate.now())
                        .lowerPart(1)
                        .middlePart(1)
                        .upperPart(1)
                        .build());

        // when
        when(interestedTreatmentPartService.updateByCustomerId(any(), anyLong()))
                .thenReturn(given);


        // then
        mockMvc.perform(put("/api/v1/customers/me/interested-treatment-parts")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(TestUtil.asJsonString(new InterestedTreatmentPartReqDTO.CreateOrUpdateOne(1, 0, 0, LocalDate.now())))
                        .header(HttpHeaders.AUTHORIZATION, "Bearer XXX"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("data.id").value(customerId))
                .andDo(document("{class-name}/{method-name}",
                        preprocessRequest(prettyPrint()),
                        preprocessResponse(prettyPrint()),
                        requestHeaders(
                                headerWithName(HttpHeaders.AUTHORIZATION).description("인증을 통해 받은 access_token 앞에 Bearer 를 붙여서 전송. ex) Bearer XXX")
                        ), queryParameters(
                                parameterWithName("upperPart").optional().description("시술 받고 싶은 부위 위쪽"),
                                parameterWithName("middlePart").optional().description("시술 받고 싶은 부위 중간"),
                                parameterWithName("lowerPart").optional().description("시술 받고 싶은 부위 아래"),
                                parameterWithName("interestSetDate").optional().description("관심 가지게 된 날짜")
                        )));
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
                .andExpect(jsonPath("data.id").value(1));
    }



    @Test
    public void testLogoutCustomerSuccess() throws Exception {

        String tokenValue = "sampleToken";

        mockMvc.perform(get("/api/v1/customers/me/logout")
                        .header("Authorization", "Bearer " + tokenValue))
                .andExpect(status().isOk())
                .andExpect(jsonPath("data.logout", is(true)));

    }

/*    @Test
    public void testLogoutCustomerFailure() throws Exception {

// OAuth2AuthorizationServiceImpl의 mock을 생성합니다.
        OAuth2AuthorizationServiceImpl mockService = Mockito.mock(OAuth2AuthorizationServiceImpl.class);

// mock 객체의 remove 메소드 호출 시 RuntimeException을 발생시킵니다.
        doThrow(new RuntimeException("Sample error")).when(mockService).remove(any(OAuth2Authorization.class));

        mockMvc.perform(get("/api/v1/customers/me/logout")
                        .header("Authorization", "Bearer " + "sample"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("data.logout", is(false)));
    }*/

    @Test
    public void createCustomer_200() throws Exception {

        // Given : 특정 값이 주어지고
        CustomerResDTO.IdWithTokenResponse idWithTokenResponse
                = new CustomerResDTO.IdWithTokenResponse(Customer.builder().id(1L).build(),
                new SpringSecuritySocialOauthDTO.TokenResponse("Bearer", "aaa", "bbb",
                        36000, "read,write", true, true));

        // When : 어떤 이벤트가 발생했을 때
        when(customerService.create(any()))
                // Then : 이 결과를 보장해야 한다.
                .thenReturn(idWithTokenResponse);

        // 보장되는 지 테스트를 한다.
        mockMvc.perform(RestDocumentationRequestBuilders.post("/api/v1/customers/create")
                        .header(CustomHttpHeaders.APP_TOKEN, "APPTOKENCCC")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\" : \"testcode_name\", " +
                                "\"birthday\" : \"" + LocalDate.parse("1980-01-01") + "\", " +
                                "\"sex\" : \"M\", " +
                                "\"hp\" : \"010-1234-1234\", " +
                                "\"telecomProvider\" : 1, " +
                                "\"idName\" : \"testcode_idName\", " +
                                "\"password\" : \"testcode_password\", " +
                                "\"email\" : \"testcode@email.com\", " +
                                "\"imei\" : \"testcde기기\", " +
                                "\"ci\" : \"testcodeCi12345\", " +
                                "\"di\" : \"testcodeDi12345\" }"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("data.id").value(1L))
                .andDo(document("{class-name}/{method-name}",
                        preprocessRequest(prettyPrint()),
                        preprocessResponse(prettyPrint()),
                        requestHeaders(
                                headerWithName(CustomHttpHeaders.APP_TOKEN).optional().description("값이 없다고 로그인이 되지는 않지만, App-Token 값이 없는 경우들은 모든 같은 access_token 을 공유합니다. 기기별 세션 정책에 따라 필수 값으로 넣어주세요.")
                        ),
                        relaxedRequestFields(
                                fieldWithPath("name").description("이름 (필수값)"),
                                fieldWithPath("birthday").description("생일 (필수값)"),
                                fieldWithPath("sex").description("성별 (필수값)"),
                                fieldWithPath("hp").description("핸드폰 번호 : 휴대폰번호 양식 체크 (필수값)"),
                                fieldWithPath("telecomProvider").description("통신사 정보 : 휴대폰본인인증 이후 넘어온 값"),
                                fieldWithPath("idName").description("아이디 : 일반회원가입시 필수값, sns회원가입은 null값으로"),
                                fieldWithPath("password").description("비밀번호 (필수값)"),
                                fieldWithPath("email").description("이메일"),
                                fieldWithPath("imei").description("단말기 정보 : 유저기기 또는 어플정보를 구분할 수 있는 값 (필수값)"),
                                fieldWithPath("ci").description("연계정보 : 휴대폰본인인증 이후 넘어온 값 (필수값)"),
                                fieldWithPath("di").description("중복확인정보 : 휴대폰본인인증 이후 넘어온 값 (필수값)")
                        ),
                        relaxedResponseFields(
                                fieldWithPath("data.id").description("신규가입 된 회원 ID")
                        )));
    }

    @Test
    public void deleteMe_200() throws Exception {

        // Given : 특정 값이 주어지고
/*        CustomerResDTO.Id id
                = new CustomerResDTO.Id(Customer.builder().id(1L).build());*/

        // When : 어떤 이벤트가 발생했을 때
/*        when(customerService.deleteCustomer(any()))
                // Then : 이 결과를 보장해야 한다.
                .thenReturn(null);*/

        // 보장되는 지 테스트를 한다.
        mockMvc.perform(RestDocumentationRequestBuilders.patch("/api/v1/customers/me/delete")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer XXX"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("data.id").value(1L))
                .andDo(document("{class-name}/{method-name}",
                        preprocessRequest(prettyPrint()),
                        preprocessResponse(prettyPrint()),
                        requestHeaders(
                                headerWithName(HttpHeaders.AUTHORIZATION).description("인증을 통해 받은 access_token 앞에 Bearer 를 붙여서 전송. ex) Bearer XXX")
                        ),
                        relaxedResponseFields(
                                fieldWithPath("data.id").description("삭제된 회원 ID")
                        )));
    }

    @Test
    public void getMeWithPushAgrees_조회_200() throws Exception {

        LocalDateTime nowTime = LocalDateTime.now();
        Long customerId = 79L;
        // Given : 특정 값이 주어지고
        CustomerResDTO.SensitiveInfoAgreeWithPushAgrees mockSensitiveInfoAgreeWithPushAgrees = new CustomerResDTO.SensitiveInfoAgreeWithPushAgrees(
                customerId, "Y", Timestamp.valueOf(nowTime), nowTime, 1, 1, nowTime,  nowTime
        );

        // When : 어떤 이벤트가 발생했을 때
        when(customerService.getMeWithPushAgrees(anyLong()))
                // Then : 이 결과를 보장해야 한다.
                .thenReturn(mockSensitiveInfoAgreeWithPushAgrees);

        // 보장되는 지 테스트를 한다.
        mockMvc.perform(get("/api/v1/customers/me/agrees")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer XXX"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("data.customerId").value(customerId))
                .andDo(document("{class-name}/{method-name}",
                        preprocessRequest(prettyPrint()),
                        preprocessResponse(prettyPrint()),
                        requestHeaders(
                                headerWithName(HttpHeaders.AUTHORIZATION).description("인증을 통해 받은 access_token 앞에 Bearer 를 붙여서 전송. ex) Bearer XXX")
                        ),relaxedResponseFields(
                                fieldWithPath("data.customerId").description("고객 ID"),
                                fieldWithPath("data.sensitiveInfo").description("민감정보 수신 동의 'N'(비동의) : 'Y'(동의)"),
                                fieldWithPath("data.sensitiveInfoCreatedAt").description("최초 민감정보 동의시간(회원가입시간)"),
                                fieldWithPath("data.sensitiveInfoUpdatedAt").description("수정 민감정보 동의시간"),
                                fieldWithPath("data.pushAgree").description("이벤트 및 혜택 알림 동의 0(비동의) : 1(동의)"),
                                fieldWithPath("data.nightPushAgree").description("야간 수신 동의 0(비동의) : 1(동의)"),
                                fieldWithPath("data.pushCreatedAt").description("최초 push 동의시간"),
                                fieldWithPath("data.pushUpdatedAt").description("수정 push 동의시간")
                        )
                ));
    }


    @Test
    public void updateMeWithPushAgrees_Success() throws Exception {

        // Given : 특정 값이 주어지고
        CustomerResDTO.Id res
                = new CustomerResDTO.Id(Customer.builder().id(79L).build());

        when(customerService.updateMeWithPushAgrees(anyLong(), any()))
                .thenReturn(res);

        // Then: Verify the expected results
        mockMvc.perform(post("/api/v1/customers/me/agrees")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer XXX")
                        .content("{\"sensitiveInfo\" : \"Y\", " +
                                "\"pushAgree\" : 1, " +
                                "\"nightPushAgree\" : 1 }"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("data.id").value(79L))
                .andDo(document("{class-name}/{method-name}",
                        preprocessRequest(prettyPrint()),
                        preprocessResponse(prettyPrint()),
                        requestHeaders(
                                headerWithName(HttpHeaders.AUTHORIZATION).description("인증을 통해 받은 access_token 앞에 Bearer 를 붙여서 전송. ex) Bearer XXX")
                        ),
                        relaxedRequestFields(
                                fieldWithPath("sensitiveInfo").description("'N' / 'Y'"),
                                fieldWithPath("pushAgree").description("0 / 1"),
                                fieldWithPath("nightPushAgree").description("0 / 1")
                        ),
                        relaxedResponseFields(
                                fieldWithPath("data.id").description("고객Id")
                        )));
    }

    @Test
    public void checkIdNameDuplicate_조회_200() throws Exception {

        String customerIdName = "test@test.com";
        when(customerService.checkIdNameDuplicate(anyString())).thenReturn(true);

        // when, then
        mockMvc.perform(get("/api/v1/customers/"+customerIdName+"/id-exists").contentType(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("data.exists").value(true))
                .andDo(document("{class-name}/{method-name}", preprocessResponse(prettyPrint())));
    }
}