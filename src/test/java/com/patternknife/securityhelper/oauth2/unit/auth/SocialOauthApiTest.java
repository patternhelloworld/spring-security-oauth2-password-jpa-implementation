package com.patternknife.securityhelper.oauth2.unit.auth;

import com.patternknife.securityhelper.oauth2.config.CustomHttpHeaders;
import com.patternknife.securityhelper.oauth2.config.response.error.GlobalExceptionHandler;
import com.patternknife.securityhelper.oauth2.config.response.error.exception.auth.NoSocialRegisteredException;
import com.patternknife.securityhelper.oauth2.config.security.principal.AccessTokenUserInfo;
import com.patternknife.securityhelper.oauth2.domain.customer.entity.Customer;
import com.patternknife.securityhelper.oauth2.domain.socialoauth.api.SocialOauthApi;
import com.patternknife.securityhelper.oauth2.domain.socialoauth.dto.SpringSecuritySocialOauthDTO;
import com.patternknife.securityhelper.oauth2.domain.socialoauth.service.SocialOauthService;
import com.patternknife.securityhelper.oauth2.util.auth.MockAuth;
import com.patternknife.securityhelper.oauth2.util.auth.UnitMockAuth;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.MethodParameter;
import org.springframework.http.MediaType;
import org.springframework.restdocs.RestDocumentationContextProvider;
import org.springframework.restdocs.RestDocumentationExtension;
import org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders;
import org.springframework.restdocs.mockmvc.RestDocumentationResultHandler;
import org.springframework.test.context.event.annotation.BeforeTestMethod;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.filter.CharacterEncodingFilter;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

import java.util.HashSet;
import java.util.Set;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.restdocs.headers.HeaderDocumentation.headerWithName;
import static org.springframework.restdocs.headers.HeaderDocumentation.requestHeaders;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.documentationConfiguration;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.preprocessResponse;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.prettyPrint;
import static org.springframework.restdocs.payload.PayloadDocumentation.*;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;


@ExtendWith(RestDocumentationExtension.class)
@ExtendWith(MockitoExtension.class)
public class SocialOauthApiTest {

    /*    @Rule
        public MockitoRule rule = MockitoJUnit.rule();*/

    private SocialOauthApi socialOauthApi;

    @Mock
    private SocialOauthService socialOauthService;


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
        MockAuth mockAuth = new UnitMockAuth();

        Customer customer = mockAuth.mockCustomerObject();
        // putAuthenticationPrincipal 에 Inject
        accessTokenUserInfo = mockAuth.mockAuthenticationPrincipal(customer);

        socialOauthApi = new SocialOauthApi(socialOauthService);

        mockMvc = MockMvcBuilders.standaloneSetup(socialOauthApi)
                .setControllerAdvice(new GlobalExceptionHandler())
                //.setCustomArgumentResolvers(putAuthenticationPrincipal)
                .apply(documentationConfiguration(restDocumentationContextProvider).uris()
                        .withScheme("https")
                        .withHost("vholic.com")
                        .withPort(8300))
                .addFilters(new CharacterEncodingFilter("UTF-8", true))
                .build();

    }


    @Test
    public void createAccessTokenUsingKaKaoToken_200() throws Exception {

        String accessToken = "sampleAccessToken123";
        String refreshToken = "sampleRefreshToken123";
        int expiresIn = 3600; // 1 hour in seconds
        Set<String> scopes = new HashSet<>();
        scopes.add("read");
        scopes.add("write");


        // Given : 특정 값이 주어지고
        SpringSecuritySocialOauthDTO.TokenResponse tokenResponse = new SpringSecuritySocialOauthDTO.TokenResponse("Bearer",
                accessToken, refreshToken, expiresIn, String.join(" ",scopes), true, false);

        // When : 어떤 이벤트가 발생했을 때
        when(socialOauthService.getAccessTokenUsingKaKaoToken(any()))
                // Then : 이 결과를 보장해야 한다.
                .thenReturn(tokenResponse);

        // 보장되는 지 테스트를 한다.
        mockMvc.perform(RestDocumentationRequestBuilders.post("/social-oauth/token/kakao")
                        .header(CustomHttpHeaders.APP_TOKEN, "APPTOKENBBB")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"clientId\": \"clientIdValue\", \"accessToken\": \"accessToken\"}"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("data.token_type").value("Bearer"))
                .andDo(document( "{class-name}/{method-name}",
                        preprocessResponse(prettyPrint()),
                        requestFields(
                                fieldWithPath("clientId").optional().description("/api/v1/traditional-oauth/token 에서 사용하는 clientId 와 동일"),
                                fieldWithPath("accessToken").optional().description("카카오 인증을 통해 받은 Access tokenstore")
                        ),relaxedResponseFields(
                                fieldWithPath("data.just_now_created").description("이번 호출로 인해 신규로 생성된 사용자인가? 아니면 기존 사용지."),
                                fieldWithPath("data.password_registered").description("해당 사용자는 password 가 등록되어있는가?")
                        )));

    }


    @Test
    public void createAccessTokenUsingKaKaoToken_NoSocialRegisteredException_401() throws Exception {

        String accessToken = "sampleAccessToken123";
        String refreshToken = "sampleRefreshToken123";
        int expiresIn = 3600; // 1 hour in seconds
        Set<String> scopes = new HashSet<>();
        scopes.add("read");
        scopes.add("write");


        // Given : 특정 값이 주어지고
        SpringSecuritySocialOauthDTO.TokenResponse tokenResponse = new SpringSecuritySocialOauthDTO.TokenResponse("Bearer",
                accessToken, refreshToken, expiresIn, String.join(" ",scopes), true, false);

        // When : 어떤 이벤트가 발생했을 때
        when(socialOauthService.getAccessTokenUsingKaKaoToken(any()))
                // Then : 이 결과를 보장해야 한다.
                .thenThrow(new NoSocialRegisteredException("인증 화면으로 연결됩니다."));

        // 보장되는 지 테스트를 한다.
        mockMvc.perform(RestDocumentationRequestBuilders.post("/social-oauth/token/kakao")
                        .header(CustomHttpHeaders.APP_TOKEN, "APPTOKENBBB")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"clientId\": \"clientIdValue\", \"accessToken\": \"accessToken\"}"))
                .andDo(print())
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("userMessage").value("인증 화면으로 연결됩니다."))
                .andDo(document( "{class-name}/{method-name}",
                        preprocessResponse(prettyPrint()),
                        requestFields(
                                fieldWithPath("clientId").optional().description("/api/v1/traditional-oauth/token 에서 사용하는 clientId 와 동일"),
                                fieldWithPath("accessToken").optional().description("카카오 인증을 통해 받은 Access tokenstore")
                        ),relaxedResponseFields(
                                fieldWithPath("timestamp").description("응답이 생성된 시간"),
                                fieldWithPath("message").description("서버의 처리되지 않은 오류로써 production 에서는 보안 상 보이지 않습니다."),
                                fieldWithPath("details").description("클라이언트가 요청 한 API 그대로 출력."),
                                fieldWithPath("userMessage").description("사용자에게 보여줄 메시지 (그대로 클라이언트 화면에 보여주세요.)")
                        )));

    }


    @Test
    public void createKakaoSocialCustomer_200() throws Exception {

        String accessToken = "sampleAccessToken123";
        String refreshToken = "sampleRefreshToken123";
        int expiresIn = 3600; // 1 hour in seconds
        Set<String> scopes = new HashSet<>();
        scopes.add("read");
        scopes.add("write");


        // Given : 특정 값이 주어지고
        SpringSecuritySocialOauthDTO.CreateCustomerResponse createCustomerResponse
                = new SpringSecuritySocialOauthDTO.CreateCustomerResponse(Customer.builder().id(10l).build(), new SpringSecuritySocialOauthDTO.TokenResponse("Bearer", "aaa", "bbb",
                36000, "read,write", true, true));

        // When : 어떤 이벤트가 발생했을 때
        when(socialOauthService.createKakaoCustomer(any()))
                // Then : 이 결과를 보장해야 한다.
                .thenReturn(createCustomerResponse);

        // 보장되는 지 테스트를 한다.
        mockMvc.perform(RestDocumentationRequestBuilders.post("/social-oauth/token/kakao/create")
                        .header(CustomHttpHeaders.APP_TOKEN, "APPTOKENBBB")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"clientId\": \"clientIdValue\", \"accessToken\": \"accessToken\"," +
                                "\"hp\": \"000-111-2222\", \"birthday\": \"2023-05-03\"," +
                                "\"sex\": \"F\", \"name\": \"aaaa\", \"telecomProvider\": 1, " +
                                "\"ci\": \"dsasdsda111\", \"di\": \"xcvxvxcsdds\"}"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("data.id").value(10L))
                .andDo(document( "{class-name}/{method-name}",
                        preprocessResponse(prettyPrint()),
                        requestHeaders(
                                headerWithName(CustomHttpHeaders.APP_TOKEN).optional().description("값이 없다고 로그인이 되지는 않지만, App-Token 값이 없는 경우들은 모든 같은 access_token 을 공유합니다. 기기별 세션 정책에 따라 필수 값으로 넣어주세요.")
                        ),
                        relaxedRequestFields(
                                fieldWithPath("clientId").optional().description("/api/v1/traditional-oauth/token 에서 사용하는 clientId 와 동일"),
                                fieldWithPath("accessToken").optional().description("카카오 인증을 통해 받은 Access tokenstore"),
                                fieldWithPath("telecomProvider").type(Integer.class).optional().description("[중요] 1 : sk, 2 : kt, 3: lg")
                        ),relaxedResponseFields(
                                fieldWithPath("data.id").description("생성된 Customer ID 입니다.")
                        )));

    }

    @Test
    public void createAccessTokenUsingNaverToken_200() throws Exception {

        String accessToken = "sampleAccessToken123";
        String refreshToken = "sampleRefreshToken123";
        int expiresIn = 3600; // 1 hour in seconds
        Set<String> scopes = new HashSet<>();
        scopes.add("read");
        scopes.add("write");


        // Given : 특정 값이 주어지고
        SpringSecuritySocialOauthDTO.TokenResponse tokenResponse = new SpringSecuritySocialOauthDTO.TokenResponse("Bearer",
                accessToken, refreshToken, expiresIn, String.join(" ",scopes), true, false);

        // When : 어떤 이벤트가 발생했을 때
        when(socialOauthService.getAccessTokenUsingNaverToken(any()))
                // Then : 이 결과를 보장해야 한다.
                .thenReturn(tokenResponse);

        // 보장되는 지 테스트를 한다.
        mockMvc.perform(RestDocumentationRequestBuilders.post("/social-oauth/token/naver")
                        .header(CustomHttpHeaders.APP_TOKEN, "APPTOKENBBB")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"clientId\": \"clientIdValue\", \"accessToken\": \"accessToken\"}"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("data.token_type").value("Bearer"))
                .andDo(document( "{class-name}/{method-name}",
                        preprocessResponse(prettyPrint()),
                        requestHeaders(
                                headerWithName(CustomHttpHeaders.APP_TOKEN).optional().description("값이 없다고 로그인이 되지는 않지만, App-Token 값이 없는 경우들은 모든 같은 access_token 을 공유합니다. 기기별 세션 정책에 따라 필수 값으로 넣어주세요.")
                        ),
                        requestFields(
                                fieldWithPath("clientId").optional().description("/api/v1/traditional-oauth/token 에서 사용하는 clientId 와 동일"),
                                fieldWithPath("accessToken").optional().description("네이버 인증을 통해 받은 Access Token")
                        ),relaxedResponseFields(
                                fieldWithPath("data.just_now_created").description("이번 호출로 인해 신규로 생성된 사용자인가? 아니면 기존 사용지."),
                                fieldWithPath("data.password_registered").description("해당 사용자는 password 가 등록되어있는가?")
                        )));

    }

    @Test
    public void createNaverSocialCustomer_200() throws Exception {

        String accessToken = "sampleAccessToken123";
        String refreshToken = "sampleRefreshToken123";
        int expiresIn = 3600; // 1 hour in seconds
        Set<String> scopes = new HashSet<>();
        scopes.add("read");
        scopes.add("write");


        // Given : 특정 값이 주어지고
        SpringSecuritySocialOauthDTO.CreateCustomerResponse createCustomerResponse
                = new SpringSecuritySocialOauthDTO.CreateCustomerResponse(Customer.builder().id(10l).build(), new SpringSecuritySocialOauthDTO.TokenResponse("Bearer", "aaa", "bbb",
                36000, "read,write", true, true));

        // When : 어떤 이벤트가 발생했을 때
        when(socialOauthService.createNaverCustomer(any()))
                // Then : 이 결과를 보장해야 한다.
                .thenReturn(createCustomerResponse);

        // 보장되는 지 테스트를 한다.
        mockMvc.perform(RestDocumentationRequestBuilders.post("/social-oauth/token/naver/create")
                        .header(CustomHttpHeaders.APP_TOKEN, "APPTOKENBBB")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"clientId\": \"clientIdValue\", \"accessToken\": \"accessToken\"," +
                                "\"hp\": \"000-111-2222\", \"birthday\": \"2023-05-02\"," +
                                "\"sex\": \"F\", \"name\": \"aaaa\", \"telecomProvider\": 1, " +
                                "\"ci\": \"dsasdsda111\", \"di\": \"xcvxvxcsdds\"}"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("data.id").value(10L))
                .andDo(document( "{class-name}/{method-name}",
                        preprocessResponse(prettyPrint()),
                        requestHeaders(
                                headerWithName(CustomHttpHeaders.APP_TOKEN).optional().description("값이 없다고 로그인이 되지는 않지만, App-Token 값이 없는 경우들은 모든 같은 access_token 을 공유합니다. 기기별 세션 정책에 따라 필수 값으로 넣어주세요.")
                        ),
                        relaxedRequestFields(
                                fieldWithPath("clientId").optional().description("/api/v1/traditional-oauth/token 에서 사용하는 clientId 와 동일"),
                                fieldWithPath("accessToken").optional().description("네이버 인증을 통해 받은 Access tokenstore"),
                                fieldWithPath("telecomProvider").type(Integer.class).optional().description("[중요] 1 : sk, 2 : kt, 3: lg")
                        ),relaxedResponseFields(
                                fieldWithPath("data.id").description("생성된 Customer ID 입니다.")
                        )));

    }


    @Test
    public void createAccessTokenUsingGoogleToken_200() throws Exception {

        String accessToken = "sampleAccessToken123";
        String refreshToken = "sampleRefreshToken123";
        int expiresIn = 3600; // 1 hour in seconds
        Set<String> scopes = new HashSet<>();
        scopes.add("read");
        scopes.add("write");


        // Given : 특정 값이 주어지고
        SpringSecuritySocialOauthDTO.TokenResponse tokenResponse = new SpringSecuritySocialOauthDTO.TokenResponse("Bearer",
                accessToken, refreshToken, expiresIn, String.join(" ",scopes), true, false);

        // When : 어떤 이벤트가 발생했을 때
        when(socialOauthService.getAccessTokenUsingGoogleToken(any()))
                // Then : 이 결과를 보장해야 한다.
                .thenReturn(tokenResponse);

        // 보장되는 지 테스트를 한다.
        mockMvc.perform(RestDocumentationRequestBuilders.post("/social-oauth/token/google")
                        .header(CustomHttpHeaders.APP_TOKEN, "APPTOKENBBB")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"clientId\": \"clientIdValue\", \"accessToken\": \"accessToken\"}"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("data.token_type").value("Bearer"))
                .andDo(document( "{class-name}/{method-name}",
                        preprocessResponse(prettyPrint()),
                        requestHeaders(
                                headerWithName(CustomHttpHeaders.APP_TOKEN).optional().description("값이 없다고 로그인이 되지는 않지만, App-Token 값이 없는 경우들은 모든 같은 access_token 을 공유합니다. 기기별 세션 정책에 따라 필수 값으로 넣어주세요.")
                        ),
                        requestFields(
                                fieldWithPath("clientId").optional().description("/api/v1/traditional-oauth/token 에서 사용하는 clientId 와 동일"),
                                fieldWithPath("accessToken").optional().description("google 인증을 통해 받은 Access Token")
                        ),relaxedResponseFields(
                                fieldWithPath("data.just_now_created").description("이번 호출로 인해 신규로 생성된 사용자인가? 아니면 기존 사용지."),
                                fieldWithPath("data.password_registered").description("해당 사용자는 password 가 등록되어있는가?")
                        )));

    }

    @Test
    public void createGoogleSocialCustomer_200() throws Exception {

        String accessToken = "sampleAccessToken123";
        String refreshToken = "sampleRefreshToken123";
        int expiresIn = 3600; // 1 hour in seconds
        Set<String> scopes = new HashSet<>();
        scopes.add("read");
        scopes.add("write");


        // Given : 특정 값이 주어지고
        SpringSecuritySocialOauthDTO.CreateCustomerResponse createCustomerResponse
                = new SpringSecuritySocialOauthDTO.CreateCustomerResponse(Customer.builder().id(10l).build(), new SpringSecuritySocialOauthDTO.TokenResponse("Bearer", "aaa", "bbb",
                36000, "read,write", true, true));

        // When : 어떤 이벤트가 발생했을 때
        when(socialOauthService.createGoogleCustomer(any()))
                // Then : 이 결과를 보장해야 한다.
                .thenReturn(createCustomerResponse);

        // 보장되는 지 테스트를 한다.
        mockMvc.perform(RestDocumentationRequestBuilders.post("/social-oauth/token/google/create")
                        .header(CustomHttpHeaders.APP_TOKEN, "APPTOKENBBB")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"clientId\": \"clientIdValue\", \"accessToken\": \"accessToken\"," +
                                "\"hp\": \"000-111-2222\", \"birthday\": \"2023-05-02\"," +
                                "\"sex\": \"F\", \"name\": \"aaaa\", \"telecomProvider\": 1, " +
                                "\"ci\": \"dsasdsda111\", \"di\": \"xcvxvxcsdds\"}"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("data.id").value(10L))
                .andDo(document( "{class-name}/{method-name}",
                        preprocessResponse(prettyPrint()),
                        requestHeaders(
                                headerWithName(CustomHttpHeaders.APP_TOKEN).optional().description("값이 없다고 로그인이 되지는 않지만, App-Token 값이 없는 경우들은 모든 같은 access_token 을 공유합니다. 기기별 세션 정책에 따라 필수 값으로 넣어주세요.")
                        ),
                        relaxedRequestFields(
                                fieldWithPath("clientId").optional().description("/api/v1/traditional-oauth/token 에서 사용하는 clientId 와 동일"),
                                fieldWithPath("accessToken").optional().description("google 인증을 통해 받은 Access tokenstore"),
                                fieldWithPath("telecomProvider").type(Integer.class).optional().description("[중요] 1 : sk, 2 : kt, 3: lg")
                        ),relaxedResponseFields(
                                fieldWithPath("data.id").description("생성된 Customer ID 입니다.")
                        )));

    }


    @Test
    public void createAppleSocialCustomer_200() throws Exception {

        String accessToken = "sampleAccessToken123";
        String refreshToken = "sampleRefreshToken123";
        int expiresIn = 3600; // 1 hour in seconds
        Set<String> scopes = new HashSet<>();
        scopes.add("read");
        scopes.add("write");


        // Given : 특정 값이 주어지고
        SpringSecuritySocialOauthDTO.CreateCustomerResponse createCustomerResponse
                = new SpringSecuritySocialOauthDTO.CreateCustomerResponse(Customer.builder().id(10l).build(), new SpringSecuritySocialOauthDTO.TokenResponse("Bearer", "aaa", "bbb",
                36000, "read,write", true, true));

        // When : 어떤 이벤트가 발생했을 때
        when(socialOauthService.createAppleCustomer(any()))
                // Then : 이 결과를 보장해야 한다.
                .thenReturn(createCustomerResponse);

        // 보장되는 지 테스트를 한다.
        mockMvc.perform(RestDocumentationRequestBuilders.post("/social-oauth/token/apple/create")
                        .header(CustomHttpHeaders.APP_TOKEN, "APPTOKENBBB")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"idToken\": \"idToken값\", \"clientId\": \"clientIdValue\"," +
                                "\"hp\": \"000-111-2222\", \"birthday\": \"2023-05-02\"," +
                                "\"sex\": \"F\", \"name\": \"aaaa\", \"telecomProvider\": 1, " +
                                "\"ci\": \"dsasdsda111\", \"di\": \"xcvxvxcsdds\"}"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("data.id").value(10L))
                .andDo(document( "{class-name}/{method-name}",
                        preprocessResponse(prettyPrint()),
                        requestHeaders(
                                headerWithName(CustomHttpHeaders.APP_TOKEN).optional().description("값이 없다고 로그인이 되지는 않지만, App-Token 값이 없는 경우들은 모든 같은 access_token 을 공유합니다. 기기별 세션 정책에 따라 필수 값으로 넣어주세요.")
                        ),
                        relaxedRequestFields(
                                fieldWithPath("clientId").optional().description("/api/v1/traditional-oauth/token 에서 사용하는 clientId 와 동일"),
                                fieldWithPath("idToken").optional().description("애플 소셜 로그인 신규 사용자 생성에만 사용하는 값. https://vholic.com:3100/auth/kt-pass/me 에서 종료하면서 전달하였다."),
                                fieldWithPath("telecomProvider").type(Integer.class).optional().description("[중요] 1 : sk, 2 : kt, 3: lg")
                        ),relaxedResponseFields(
                                fieldWithPath("data.id").description("생성된 Customer ID 입니다.")
                        )));

    }



}