package io.github.patternknife.securityhelper.oauth2.api.config.security.server;


import io.github.patternknife.securityhelper.oauth2.api.config.security.aop.DefaultSecurityPointCut;
import io.github.patternknife.securityhelper.oauth2.api.config.security.aop.SecurityPointCut;
import io.github.patternknife.securityhelper.oauth2.api.config.security.converter.auth.endpoint.AuthorizationCodeAuthorizationRequestConverter;
import io.github.patternknife.securityhelper.oauth2.api.config.security.converter.auth.endpoint.IntrospectionRequestConverter;
import io.github.patternknife.securityhelper.oauth2.api.config.security.converter.auth.endpoint.PasswordAccessTokenRequestConverter;
import io.github.patternknife.securityhelper.oauth2.api.config.security.dao.KnifeAuthorizationConsentRepository;
import io.github.patternknife.securityhelper.oauth2.api.config.security.introspector.DefaultResourceServerTokenIntrospector;
import io.github.patternknife.securityhelper.oauth2.api.config.security.message.DefaultSecurityMessageServiceImpl;
import io.github.patternknife.securityhelper.oauth2.api.config.security.message.ISecurityUserExceptionMessageService;
import io.github.patternknife.securityhelper.oauth2.api.config.security.provider.auth.endpoint.AuthorizationCodeAuthenticationProvider;
import io.github.patternknife.securityhelper.oauth2.api.config.security.provider.auth.endpoint.PasswordAuthenticationProvider;
import io.github.patternknife.securityhelper.oauth2.api.config.security.provider.auth.introspectionendpoint.IntrospectOpaqueTokenAuthenticationProvider;
import io.github.patternknife.securityhelper.oauth2.api.config.security.response.auth.authentication.DefaultApiAuthenticationFailureHandlerImpl;
import io.github.patternknife.securityhelper.oauth2.api.config.security.response.auth.authentication.DefaultApiAuthenticationSuccessHandlerImpl;
import io.github.patternknife.securityhelper.oauth2.api.config.security.response.auth.authentication.DefaultWebAuthenticationFailureHandlerImpl;
import io.github.patternknife.securityhelper.oauth2.api.config.security.response.auth.authentication.DefaultWebAuthenticationSuccessHandlerImpl;
import io.github.patternknife.securityhelper.oauth2.api.config.security.response.resource.authentication.DefaultAuthenticationEntryPoint;
import io.github.patternknife.securityhelper.oauth2.api.config.security.serivce.CommonOAuth2AuthorizationSaver;
import io.github.patternknife.securityhelper.oauth2.api.config.security.serivce.DefaultOauth2AuthenticationHashCheckService;
import io.github.patternknife.securityhelper.oauth2.api.config.security.serivce.persistence.authorization.OAuth2AuthorizationConsentServiceImpl;
import io.github.patternknife.securityhelper.oauth2.api.config.security.serivce.persistence.authorization.OAuth2AuthorizationServiceImpl;
import io.github.patternknife.securityhelper.oauth2.api.config.security.serivce.persistence.client.RegisteredClientRepositoryImpl;
import io.github.patternknife.securityhelper.oauth2.api.config.security.serivce.userdetail.ConditionalDetailsService;
import io.github.patternknife.securityhelper.oauth2.api.config.security.token.generator.CustomDelegatingOAuth2TokenGenerator;
import io.github.patternknife.securityhelper.oauth2.api.config.util.KnifeOrderConstants;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
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
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
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

@Order(KnifeOrderConstants.SECURITY_KNIFE_SERVER_CONFIG_ORDER)
@Configuration
@RequiredArgsConstructor
@EnableMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true)
public class KnifeServerConfig {

    private static final Logger logger = LoggerFactory.getLogger(KnifeServerConfig.class);

    @Primary
    @Bean
    public OAuth2TokenGenerator<OAuth2Token> tokenGenerator(JwtEncoder jwtEncoder) {

        JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
        return new CustomDelegatingOAuth2TokenGenerator(
                jwtGenerator,
                new OAuth2RefreshTokenGenerator()
        );
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
            @Qualifier("apiAuthenticationFailureHandler") AuthenticationFailureHandler iApiAuthenticationFailureHandler,
            @Qualifier("apiAuthenticationSuccessHandler") AuthenticationSuccessHandler iApiAuthenticationSuccessHandler,
            @Qualifier("webAuthenticationFailureHandler") AuthenticationFailureHandler iWebAuthenticationFailureHandler,
            @Qualifier("webAuthenticationSuccessHandler") AuthenticationSuccessHandler iWebAuthenticationSuccessHandler) throws Exception {

        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();


        http.with(authorizationServerConfigurer, Customizer.withDefaults());

        authorizationServerConfigurer
                .clientAuthentication(clientAuthentication ->
                        clientAuthentication
                                .errorResponseHandler(iApiAuthenticationFailureHandler)
                )
                .registeredClientRepository(registeredClientRepository)
                .authorizationService(authorizationService)
                .tokenGenerator(tokenGenerator)
                .oidc(Customizer.withDefaults())
                /*
                 *
                 *    Authorization Code
                 *
                 *    : /oauth2/authorize
                 *
                 *    TO DO. //  https://medium.com/@itsinil/oauth-2-1-pkce-%EB%B0%A9%EC%8B%9D-%EC%95%8C%EC%95%84%EB%B3%B4%EA%B8%B0-14500950cdbf
                 *
                 *    http://localhost:8370/oauth2/authorize?response_type=code&client_id=client_customer&state=xxx&scope=read&redirect_uri=http%3A%2F%2Flocalhost%3A8081%2Fcallback1
                 * */
                .authorizationEndpoint(authorizationEndpoint ->
                        authorizationEndpoint
                                // Converter
                                .authorizationRequestConverter(new AuthorizationCodeAuthorizationRequestConverter(registeredClientRepository, knifeAuthorizationConsentRepository, authorizationService))
                                // Provider
                                .authenticationProvider(new AuthorizationCodeAuthenticationProvider(
                                        authorizationService, tokenGenerator, conditionalDetailsService, commonOAuth2AuthorizationSaver
                                ))
                                // Response (Success)
                                .authorizationResponseHandler(iWebAuthenticationSuccessHandler)
                                // Response (Failure)
                                .errorResponseHandler(iWebAuthenticationFailureHandler)

                )
                /*
                 *
                 *    1) ROPC (grant_type=password, grant_type=refresh_token)
                 *    2) Authorization Code flow
                 *      - Get an authorization_code with username and password (grant_type=authorization_code)
                 *      - Login with code received from the authorization code flow instead of username & password (grant_type=code)
                 *
                 *    : /oauth2/authorize
                 *
                 * * */
                .tokenEndpoint(tokenEndpoint ->
                        tokenEndpoint
                                // Converter
                                .accessTokenRequestConverter(new PasswordAccessTokenRequestConverter())
                                // Provider
                                .authenticationProvider(new PasswordAuthenticationProvider(
                                        commonOAuth2AuthorizationSaver, conditionalDetailsService, oauth2AuthenticationHashCheckService,
                                        authorizationService, iSecurityUserExceptionMessageService
                                ))
                                // Response (Success)
                                .accessTokenResponseHandler(iApiAuthenticationSuccessHandler)
                                // Response (Failure)
                                .errorResponseHandler(iApiAuthenticationFailureHandler)

                )
                /*
                *   : /oauth2/introspect
                * */
                .tokenIntrospectionEndpoint(tokenIntrospectEndpoint ->
                        tokenIntrospectEndpoint
                                // Converter
                                .introspectionRequestConverter(httpServletRequest -> new IntrospectionRequestConverter(
                                ).convert(httpServletRequest))
                                // Provider
                                .authenticationProvider(new IntrospectOpaqueTokenAuthenticationProvider(
                                      authorizationService, conditionalDetailsService
                                )));

        RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();

        http.csrf(AbstractHttpConfigurer::disable)
                .securityMatcher(endpointsMatcher)
                .formLogin(formLogin -> formLogin
                        .loginPage("/login")
                        .permitAll()
                )
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/login/**", "/oauth2/**").permitAll()
                        .anyRequest().authenticated()
                ).exceptionHandling(exceptions -> exceptions.
                        authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")));

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
    @Order(2)
    public SecurityFilterChain resourceServerSecurityFilterChain(HttpSecurity http, OAuth2AuthorizationServiceImpl authorizationService,
                                                                 ConditionalDetailsService conditionalDetailsService,
                                                                 ISecurityUserExceptionMessageService iSecurityUserExceptionMessageService,
                                                                 AuthenticationEntryPoint iAuthenticationEntryPoint, OpaqueTokenIntrospector opaqueTokenIntrospector
    ) throws Exception {

        DefaultBearerTokenResolver resolver = new DefaultBearerTokenResolver();
        resolver.setAllowFormEncodedBodyParameter(true);

        http.csrf(AbstractHttpConfigurer::disable)
                .oauth2ResourceServer(oauth2 -> oauth2
                        .bearerTokenResolver(resolver)
                        .authenticationEntryPoint(iAuthenticationEntryPoint)
                        .opaqueToken(opaqueToken -> opaqueToken.introspector(opaqueTokenIntrospector)));

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


    // API : Generally for ROPC

    @Bean(name = "apiAuthenticationFailureHandler")
    @ConditionalOnMissingBean(name = "apiAuthenticationFailureHandler")
    public AuthenticationFailureHandler iApiAuthenticationFailureHandler(ISecurityUserExceptionMessageService iSecurityUserExceptionMessageService) {
        return new DefaultApiAuthenticationFailureHandlerImpl(iSecurityUserExceptionMessageService);
    }
    @Bean(name = "apiAuthenticationSuccessHandler")
    @ConditionalOnMissingBean(name = "apiAuthenticationSuccessHandler")
    public AuthenticationSuccessHandler iApiAuthenticationSuccessHandler(ISecurityUserExceptionMessageService iSecurityUserExceptionMessageService) {
        return new DefaultApiAuthenticationSuccessHandlerImpl(iSecurityUserExceptionMessageService);
    }


    // WEB : Generally for Authorization Code

    @Bean(name = "webAuthenticationFailureHandler")
    @ConditionalOnMissingBean(name = "webAuthenticationFailureHandler")
    public AuthenticationFailureHandler iWebAuthenticationFailureHandler(ISecurityUserExceptionMessageService iSecurityUserExceptionMessageService) {
        return new DefaultWebAuthenticationFailureHandlerImpl(iSecurityUserExceptionMessageService);
    }
    @Bean(name = "webAuthenticationSuccessHandler")
    @ConditionalOnMissingBean(name = "webAuthenticationSuccessHandler")
    public AuthenticationSuccessHandler iWebAuthenticationSuccessHandler(ISecurityUserExceptionMessageService iSecurityUserExceptionMessageService) {
        return new DefaultWebAuthenticationSuccessHandlerImpl(iSecurityUserExceptionMessageService);
    }



    /*
     *    Resource
     * */
    @Bean
    @ConditionalOnMissingBean(AuthenticationEntryPoint.class)
    public AuthenticationEntryPoint iAuthenticationEntryPoint(@Qualifier("handlerExceptionResolver") HandlerExceptionResolver resolver) {
        return new DefaultAuthenticationEntryPoint(resolver);
    }

    @Bean
    @ConditionalOnMissingBean(OpaqueTokenIntrospector.class)
    public OpaqueTokenIntrospector tokenIntrospector(OAuth2AuthorizationServiceImpl authorizationService,
                                                     ConditionalDetailsService conditionalDetailsService, ISecurityUserExceptionMessageService iSecurityUserExceptionMessageService,
                                                     @Value("${patternknife.securityhelper.oauth2.introspection.type:database}") String introspectionType,
                                                     @Value("${patternknife.securityhelper.oauth2.introspection.uri:default-introspect-uri}") String introspectionUri,
                                                     @Value("${patternknife.securityhelper.oauth2.introspection.client-id:default-client-id}") String clientId,
                                                     @Value("${patternknife.securityhelper.oauth2.introspection.client-secret:default-client-secret}") String clientSecret,
                                                     JwtDecoder jwtDecoder) {
        return new DefaultResourceServerTokenIntrospector(authorizationService, conditionalDetailsService, iSecurityUserExceptionMessageService, introspectionType, introspectionUri, clientId, clientSecret, jwtDecoder);
    }
}