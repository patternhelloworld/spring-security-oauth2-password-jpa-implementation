package io.github.patternknife.securityhelper.oauth2.api.config.security.server;


import io.github.patternknife.securityhelper.oauth2.api.config.security.aop.DefaultSecurityPointCut;
import io.github.patternknife.securityhelper.oauth2.api.config.security.aop.SecurityPointCut;
import io.github.patternknife.securityhelper.oauth2.api.config.security.converter.auth.endpoint.AuthorizationCodeRequestAuthenticationConverter;
import io.github.patternknife.securityhelper.oauth2.api.config.security.converter.auth.endpoint.KnifeAccessTokenAuthenticationConverter;
import io.github.patternknife.securityhelper.oauth2.api.config.security.dao.KnifeAuthorizationConsentRepository;
import io.github.patternknife.securityhelper.oauth2.api.config.security.message.DefaultSecurityMessageServiceImpl;
import io.github.patternknife.securityhelper.oauth2.api.config.security.message.ISecurityUserExceptionMessageService;
import io.github.patternknife.securityhelper.oauth2.api.config.security.provider.auth.endpoint.KnifeOauth2AuthenticationProvider;

import io.github.patternknife.securityhelper.oauth2.api.config.security.provider.auth.endpoint.KnifeOauth2AuthorizationCodeAuthenticationProvider;
import io.github.patternknife.securityhelper.oauth2.api.config.security.provider.auth.introspectionendpoint.KnifeOauth2OpaqueTokenAuthenticationProvider;
import io.github.patternknife.securityhelper.oauth2.api.config.security.response.auth.authentication.DefaultAuthenticationFailureHandlerImpl;
import io.github.patternknife.securityhelper.oauth2.api.config.security.response.auth.authentication.DefaultAuthenticationSuccessHandlerImpl;
import io.github.patternknife.securityhelper.oauth2.api.config.security.response.error.exception.KnifeOauth2AuthenticationException;
import io.github.patternknife.securityhelper.oauth2.api.config.security.response.resource.authentication.DefaultAuthenticationEntryPoint;
import io.github.patternknife.securityhelper.oauth2.api.config.security.serivce.CommonOAuth2AuthorizationSaver;
import io.github.patternknife.securityhelper.oauth2.api.config.security.serivce.DefaultOauth2AuthenticationHashCheckService;
import io.github.patternknife.securityhelper.oauth2.api.config.security.serivce.IOauth2AuthenticationHashCheckService;
import io.github.patternknife.securityhelper.oauth2.api.config.security.serivce.persistence.authorization.OAuth2AuthorizationConsentServiceImpl;
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
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken;
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

import org.springframework.web.servlet.HandlerExceptionResolver;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;


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
            OAuth2AuthorizationConsentServiceImpl oAuth2AuthorizationConsentService,
            AuthenticationFailureHandler iAuthenticationFailureHandler, AuthenticationSuccessHandler iAuthenticationSuccessHandler) throws Exception {

        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();


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
                 *
                 *    Authorization Code
                 *
                 *    TO DO. //  https://medium.com/@itsinil/oauth-2-1-pkce-%EB%B0%A9%EC%8B%9D-%EC%95%8C%EC%95%84%EB%B3%B4%EA%B8%B0-14500950cdbf
                 *
                 *    http://localhost:8370/oauth2/authorize?response_type=code&client_id=client_customer&state=xxx&scope=read&redirect_uri=http%3A%2F%2Flocalhost%3A8081%2Fcallback1
                 * */
                .authorizationEndpoint(authorizationEndpoint ->
                        authorizationEndpoint
                                .authorizationRequestConverter(new AuthorizationCodeRequestAuthenticationConverter(registeredClientRepository, knifeAuthorizationConsentRepository, authorizationService))
                                .authenticationProvider(new KnifeOauth2AuthorizationCodeAuthenticationProvider(
                                        authorizationService, tokenGenerator, conditionalDetailsService, commonOAuth2AuthorizationSaver
                                )).authorizationResponseHandler(new AuthenticationSuccessHandler() {
                                    @Override
                                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                                        OAuth2AuthorizationCodeAuthenticationToken oAuth2AuthorizationCodeAuthenticationToken = (OAuth2AuthorizationCodeAuthenticationToken) authentication;

                                        String redirectUri = oAuth2AuthorizationCodeAuthenticationToken.getRedirectUri();
                                        String authorizationCode = oAuth2AuthorizationCodeAuthenticationToken.getCode();
                                        String state = oAuth2AuthorizationCodeAuthenticationToken.getAdditionalParameters().get("state").toString();

                                        response.sendRedirect(redirectUri+"?code="+authorizationCode+"&state="+state);
                                    }
                                }
                                )
                                .errorResponseHandler(new AuthenticationFailureHandler() {
                                    @Override
                                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                                        // SecurityKnifeExceptionHandler does NOT handle this error.
                                        logger.error("Authentication failed: ", exception);

                                        String errorMessage = "An unexpected error occurred.";
                                        List<String> errorDetails = new ArrayList<>();
                                        // Extract error messages if the exception is of type KnifeOauth2AuthenticationException
                                        if (exception instanceof KnifeOauth2AuthenticationException) {
                                            KnifeOauth2AuthenticationException oauth2Exception = (KnifeOauth2AuthenticationException) exception;
                                            errorMessage = oauth2Exception.getErrorMessages().getUserMessage();
                                        }

                                        if(errorMessage.equals("Authorization code missing in GET request")){
                                            request.getRequestDispatcher("/login").forward(request, response);
                                        }else {

                                            // Redirect to /error with query parameters
                                            request.setAttribute("errorMessage", errorMessage);
                                            request.setAttribute("errorDetails", errorDetails);

                                            request.getRequestDispatcher("/error").forward(request, response);
                                        }
                                    }
                                })

                )
                /*
                 *    1) ROPC (grant_type=password, grant_type=refresh_token)
                 *    2) Authorization Code flow
                 *      - Get an authorization_code with username and password (grant_type=authorization_code)
                 *      - Login with code received from the authorization code flow instead of username & password (grant_type=code)
                 * */
                .tokenEndpoint(tokenEndpoint ->
                        tokenEndpoint
                                .accessTokenResponseHandler(iAuthenticationSuccessHandler)
                                .accessTokenRequestConverter(new KnifeAccessTokenAuthenticationConverter())
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
