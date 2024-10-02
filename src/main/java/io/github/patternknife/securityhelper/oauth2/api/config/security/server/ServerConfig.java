package io.github.patternknife.securityhelper.oauth2.api.config.security.server;


import io.github.patternknife.securityhelper.oauth2.api.config.security.aop.DefaultSecurityPointCut;
import io.github.patternknife.securityhelper.oauth2.api.config.security.aop.SecurityPointCut;
import io.github.patternknife.securityhelper.oauth2.api.config.security.converter.auth.endpoint.AuthorizationCodeAuthenticationConverter;
import io.github.patternknife.securityhelper.oauth2.api.config.security.converter.auth.endpoint.AuthorizationCodeRequestAuthenticationConverter;
import io.github.patternknife.securityhelper.oauth2.api.config.security.converter.auth.endpoint.PasswordAuthenticationConverter;
import io.github.patternknife.securityhelper.oauth2.api.config.security.dao.KnifeAuthorizationConsentRepository;
import io.github.patternknife.securityhelper.oauth2.api.config.security.message.DefaultSecurityMessageServiceImpl;
import io.github.patternknife.securityhelper.oauth2.api.config.security.message.ISecurityUserExceptionMessageService;
import io.github.patternknife.securityhelper.oauth2.api.config.security.provider.auth.endpoint.KnifeOauth2AuthenticationProvider;
import io.github.patternknife.securityhelper.oauth2.api.config.security.provider.auth.introspectionendpoint.KnifeOauth2OpaqueTokenAuthenticationProvider;
import io.github.patternknife.securityhelper.oauth2.api.config.security.response.auth.authentication.DefaultAuthenticationFailureHandlerImpl;
import io.github.patternknife.securityhelper.oauth2.api.config.security.response.auth.authentication.DefaultAuthenticationSuccessHandlerImpl;
import io.github.patternknife.securityhelper.oauth2.api.config.security.response.resource.authentication.DefaultAuthenticationEntryPoint;
import io.github.patternknife.securityhelper.oauth2.api.config.security.serivce.CommonOAuth2AuthorizationSaver;
import io.github.patternknife.securityhelper.oauth2.api.config.security.serivce.DefaultOauth2AuthenticationHashCheckService;
import io.github.patternknife.securityhelper.oauth2.api.config.security.serivce.IOauth2AuthenticationHashCheckService;
import io.github.patternknife.securityhelper.oauth2.api.config.security.serivce.persistence.authorization.OAuth2AuthorizationServiceImpl;
import io.github.patternknife.securityhelper.oauth2.api.config.security.serivce.persistence.client.RegisteredClientRepositoryImpl;
import io.github.patternknife.securityhelper.oauth2.api.config.security.serivce.userdetail.ConditionalDetailsService;
import io.github.patternknife.securityhelper.oauth2.api.config.security.token.generator.CustomDelegatingOAuth2TokenGenerator;

import io.github.patternknife.securityhelper.oauth2.api.config.security.provider.resource.introspector.JpaTokenStoringOauth2TokenIntrospector;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.servlet.HandlerExceptionResolver;

import java.io.IOException;

@Configuration
@RequiredArgsConstructor
@EnableMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true)
public class ServerConfig {

    private static final Logger logger = LoggerFactory.getLogger(ServerConfig.class);

    private static String CUSTOM_CONSENT_PAGE_URI = "/oauth2/authorization";

    @Primary
    @Bean
    public OAuth2TokenGenerator<OAuth2Token> tokenGenerator() {
        OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
        OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();
        return new CustomDelegatingOAuth2TokenGenerator(
                accessTokenGenerator, refreshTokenGenerator);
    }



    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(
            HttpSecurity http,
            CommonOAuth2AuthorizationSaver commonOAuth2AuthorizationSaver,
            OAuth2AuthorizationServiceImpl authorizationService,
            ConditionalDetailsService conditionalDetailsService,
            DefaultOauth2AuthenticationHashCheckService oauth2AuthenticationHashCheckService,
            OAuth2TokenGenerator<?> tokenGenerator,
            RegisteredClientRepositoryImpl registeredClientRepository,
            KnifeAuthorizationConsentRepository knifeAuthorizationConsentRepository,
            ISecurityUserExceptionMessageService iSecurityUserExceptionMessageService,
            AuthenticationFailureHandler iAuthenticationFailureHandler, AuthenticationSuccessHandler iAuthenticationSuccessHandler) throws Exception {

        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();

/*
        Function<OidcUserInfoAuthenticationContext, OidcUserInfo> userInfoMapper = (context) -> {
            OidcUserInfoAuthenticationToken authentication = context.getAuthentication();
            return new OidcUserInfo(conditionalDetailsService.loadUserByUsername(authentication.getName(), registeredClientRepository).getClaims());
        };
*/



        http.with(authorizationServerConfigurer, Customizer.withDefaults());

        authorizationServerConfigurer
                .clientAuthentication(clientAuthentication ->
                        clientAuthentication
                                .errorResponseHandler(iAuthenticationFailureHandler)
                )
                .registeredClientRepository(registeredClientRepository)
                .authorizationService(authorizationService)
                .tokenGenerator(tokenGenerator)
                .oidc(Customizer.withDefaults())
                /*
                 *    https://sabarada.tistory.com/248
                 *
                 *    code, client_id, redirect_uri
                 *    http://localhost:8370/oauth2/authorization?code=32132&response_type=code&client_id=client_customer&redirect_uri=http%3A%2F%2Flocalhost%3A8370%2Fcallback1
                 *
                 * */
                //  https://medium.com/@itsinil/oauth-2-1-pkce-%EB%B0%A9%EC%8B%9D-%EC%95%8C%EC%95%84%EB%B3%B4%EA%B8%B0-14500950cdbf
                .authorizationEndpoint(authorizationEndpoint ->
                        authorizationEndpoint
                                // [1] User goes to the 'consentPage' below ('http://localhost:8370/oauth2/authorization?code=XXXXX&response_type=code&client_id=client_customer&redirect_uri=http%3A%2F%2Flocalhost%3A8370%2Fcallback1&scope=message.read&state=random-state&prompt=consent&access_type=offline&code_challenge=YOUR_CODE_CHALLENGE&code_challenge_method=S256')
                                // [2] As you see 'KnifeAuthorizationCodeRequestConverterController', if the code parameter is NOT authenticated, it redirects you to the login page.
                                // [3] If the login (/api/v1/traditional-oauth/authorization-code) in the 'src/main/resources/templates/login.html' is successful, it retries [1].
                                // [4] Now you are on the consent page, check READ & WRITE and then press 'Submit'.
                                .consentPage(CUSTOM_CONSENT_PAGE_URI)
                                // [5]
                                .authorizationRequestConverter(new AuthorizationCodeRequestAuthenticationConverter(registeredClientRepository, knifeAuthorizationConsentRepository, authorizationService))
                    /*            .authorizationRequestConverter(new AuthorizationCodeRequestAuthenticationConverter(registeredClientRepository, knifeAuthorizationConsentRepository))
                                .authorizationRequestConverters(conveterList -> {
                                    conveterList.add(new AuthorizationCodeAuthenticationConverter(registeredClientRepository));
                                })*/
                                .authorizationRequestConverters(conveterList -> {
                                    conveterList.add(new AuthorizationCodeAuthenticationConverter(registeredClientRepository));
                                })
                                .errorResponseHandler(iAuthenticationFailureHandler)
                                .authenticationProvider(new KnifeOauth2AuthenticationProvider(
                                        commonOAuth2AuthorizationSaver,
                                        conditionalDetailsService,
                                        oauth2AuthenticationHashCheckService,
                                        authorizationService,
                                        iSecurityUserExceptionMessageService
                                )).authorizationResponseHandler(new AuthenticationSuccessHandler() {
                                    @Override
                                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                                        OAuth2AuthorizationCodeRequestAuthenticationToken authentication1 = (OAuth2AuthorizationCodeRequestAuthenticationToken) authentication;
                                        System.out.println(authentication);
                                        String redirectUri = authentication1.getRedirectUri();
                                        String authorizationCode = authentication1.getAuthorizationCode().getTokenValue();
                                        String state = null;
                                        if (StringUtils.hasText(authentication1.getState())) {
                                            state = authentication1.getState();
                                        }
                                        response.sendRedirect(redirectUri+"?code="+authorizationCode+"&state="+state);
                                    }
                                }
                                )
                                .errorResponseHandler(new AuthenticationFailureHandler() {
                                    @Override
                                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {

                                        logger.error(exception.toString());
                                        response.sendRedirect("login");
                                    }
                                })

                )
                /*
                *
                *    /oauth2/token
                * */
                .tokenEndpoint(tokenEndpoint ->
                        tokenEndpoint
                                .accessTokenResponseHandler(iAuthenticationSuccessHandler)
                                .accessTokenRequestConverter(new PasswordAuthenticationConverter())
                                // found only Oauth2AuthenticationException is tossed.
                                .errorResponseHandler(iAuthenticationFailureHandler)
                                .authenticationProvider(new KnifeOauth2AuthenticationProvider(
                                        commonOAuth2AuthorizationSaver, conditionalDetailsService, oauth2AuthenticationHashCheckService,
                                        authorizationService, iSecurityUserExceptionMessageService
                                ))

                ).tokenIntrospectionEndpoint(tokenIntrospectEndpoint ->
                        tokenIntrospectEndpoint
                                .introspectionRequestConverter(httpServletRequest -> new KnifeOauth2OpaqueTokenAuthenticationProvider(
                                        tokenIntrospector(
                                                authorizationService, conditionalDetailsService, iSecurityUserExceptionMessageService
                                        ),authorizationService, conditionalDetailsService
                                ).convert(httpServletRequest))
                                .authenticationProvider(new KnifeOauth2OpaqueTokenAuthenticationProvider(
                                        tokenIntrospector(
                                                authorizationService, conditionalDetailsService, iSecurityUserExceptionMessageService
                                        ),authorizationService, conditionalDetailsService
                                )).errorResponseHandler(iAuthenticationFailureHandler));

        RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();

        http.csrf(AbstractHttpConfigurer::disable)
                .securityMatcher(endpointsMatcher)
                .formLogin(formLogin -> formLogin
                        .loginPage("/login")  // 커스터마이징된 로그인 페이지 경로
                        .permitAll()
                )
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/login/**", "/oauth2/**").permitAll()
                        .anyRequest().authenticated()
                ).exceptionHandling(exceptions -> exceptions.
                        authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")));


//        http.exceptionHandling(exceptions -> exceptions.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")));;
        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Primary
    @Bean
    BearerTokenResolver bearerTokenResolver() {
        DefaultBearerTokenResolver bearerTokenResolver = new DefaultBearerTokenResolver();
        bearerTokenResolver.setBearerTokenHeaderName(HttpHeaders.AUTHORIZATION);
        return bearerTokenResolver;
    }

    @Bean
    public OpaqueTokenIntrospector tokenIntrospector(OAuth2AuthorizationServiceImpl authorizationService,
                                                     ConditionalDetailsService conditionalDetailsService, ISecurityUserExceptionMessageService iSecurityUserExceptionMessageService) {
        return new JpaTokenStoringOauth2TokenIntrospector(authorizationService, conditionalDetailsService, iSecurityUserExceptionMessageService);
    }

    @Bean
    @Order(2)
    public SecurityFilterChain resourceServerSecurityFilterChain(HttpSecurity http, OAuth2AuthorizationServiceImpl authorizationService,
                                                                 ConditionalDetailsService conditionalDetailsService,
                                                                 ISecurityUserExceptionMessageService iSecurityUserExceptionMessageService,
                                                                 AuthenticationEntryPoint iAuthenticationEntryPoint
    ) throws Exception {

        DefaultBearerTokenResolver resolver = new DefaultBearerTokenResolver();
        resolver.setAllowFormEncodedBodyParameter(true);

        http.csrf(AbstractHttpConfigurer::disable)
                .oauth2ResourceServer(oauth2 -> oauth2
                        .bearerTokenResolver(resolver)
                        .authenticationEntryPoint(iAuthenticationEntryPoint)
                        .opaqueToken(opaqueToken -> opaqueToken.introspector(tokenIntrospector(authorizationService, conditionalDetailsService, iSecurityUserExceptionMessageService))));

        return http.build();
    }


    @Bean
    @ConditionalOnMissingBean(SecurityPointCut.class)
    public SecurityPointCut securityPointCut() {
        return new DefaultSecurityPointCut();
    }

    @Bean
    @ConditionalOnMissingBean(ISecurityUserExceptionMessageService.class)
    public ISecurityUserExceptionMessageService securityUserExceptionMessageService() {
        return new DefaultSecurityMessageServiceImpl();
    }


    /*
     *    Auth
     * */
    @Bean
    @ConditionalOnMissingBean(AuthenticationFailureHandler.class)
    public AuthenticationFailureHandler iAuthenticationFailureHandler(ISecurityUserExceptionMessageService iSecurityUserExceptionMessageService) {
        return new DefaultAuthenticationFailureHandlerImpl(iSecurityUserExceptionMessageService);
    }

    @Bean
    @ConditionalOnMissingBean(AuthenticationSuccessHandler.class)
    public AuthenticationSuccessHandler iAuthenticationSuccessHandler(ISecurityUserExceptionMessageService iSecurityUserExceptionMessageService) {
        return new DefaultAuthenticationSuccessHandlerImpl(iSecurityUserExceptionMessageService);
    }
    @Bean
    @ConditionalOnMissingBean(IOauth2AuthenticationHashCheckService.class)
    public IOauth2AuthenticationHashCheckService iOauth2AuthenticationHashCheckService(ISecurityUserExceptionMessageService iSecurityUserExceptionMessageService) {
        return new DefaultOauth2AuthenticationHashCheckService(passwordEncoder(), iSecurityUserExceptionMessageService);
    }


    /*
     *    Resource
     * */
    @Bean
    @ConditionalOnMissingBean(AuthenticationEntryPoint.class)
    public AuthenticationEntryPoint iAuthenticationEntryPoint(@Qualifier("handlerExceptionResolver") HandlerExceptionResolver resolver) {
        return new DefaultAuthenticationEntryPoint(resolver);
    }

}
