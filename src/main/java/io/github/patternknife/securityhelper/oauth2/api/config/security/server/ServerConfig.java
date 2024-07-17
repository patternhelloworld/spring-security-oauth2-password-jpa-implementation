package io.github.patternknife.securityhelper.oauth2.api.config.security.server;


import io.github.patternknife.securityhelper.oauth2.api.config.security.aop.DefaultSecurityPointCut;
import io.github.patternknife.securityhelper.oauth2.api.config.security.aop.SecurityPointCut;
import io.github.patternknife.securityhelper.oauth2.api.config.security.converter.auth.endpoint.CustomGrantAuthenticationConverter;
import io.github.patternknife.securityhelper.oauth2.api.config.security.errorhandler.auth.authentication.DefaultAuthenticationFailureHandlerImpl;
import io.github.patternknife.securityhelper.oauth2.api.config.security.errorhandler.resource.authentication.AuthenticationEntryPointToGlobalExceptionHandler;

import io.github.patternknife.securityhelper.oauth2.api.config.security.message.DefaultSecurityMessageServiceImpl;
import io.github.patternknife.securityhelper.oauth2.api.config.security.message.ISecurityUserExceptionMessageService;
import io.github.patternknife.securityhelper.oauth2.api.config.security.provider.auth.endpoint.KnifeOauth2AuthenticationProvider;
import io.github.patternknife.securityhelper.oauth2.api.config.security.provider.auth.introspectionendpoint.Oauth2OpaqueTokenAuthenticationProvider;
import io.github.patternknife.securityhelper.oauth2.api.config.security.provider.resource.introspector.JpaTokenStoringOauth2TokenIntrospector;
import io.github.patternknife.securityhelper.oauth2.api.config.security.serivce.CommonOAuth2AuthorizationCycle;
import io.github.patternknife.securityhelper.oauth2.api.config.security.serivce.Oauth2AuthenticationHashCheckService;
import io.github.patternknife.securityhelper.oauth2.api.config.security.serivce.persistence.authorization.OAuth2AuthorizationServiceImpl;
import io.github.patternknife.securityhelper.oauth2.api.config.security.serivce.persistence.client.RegisteredClientRepositoryImpl;
import io.github.patternknife.securityhelper.oauth2.api.config.security.serivce.userdetail.ConditionalDetailsService;
import io.github.patternknife.securityhelper.oauth2.api.config.security.token.TokenResponseSuccessHandler;
import io.github.patternknife.securityhelper.oauth2.api.config.security.token.generator.CustomDelegatingOAuth2TokenGenerator;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.servlet.HandlerExceptionResolver;

@Configuration
@RequiredArgsConstructor
@EnableMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true)
public class ServerConfig {

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
            CommonOAuth2AuthorizationCycle commonOAuth2AuthorizationCycle,
            OAuth2AuthorizationServiceImpl authorizationService,
            ConditionalDetailsService conditionalDetailsService,
            Oauth2AuthenticationHashCheckService oauth2AuthenticationHashCheckService,
            OAuth2TokenGenerator<?> tokenGenerator,
            RegisteredClientRepositoryImpl registeredClientRepository,
            ISecurityUserExceptionMessageService iSecurityUserExceptionMessageService,
            AuthenticationFailureHandler iAuthenticationFailureHandler) throws Exception {

        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();

        http.apply(authorizationServerConfigurer);

        authorizationServerConfigurer
                .clientAuthentication(clientAuthentication ->
                        clientAuthentication
                                .errorResponseHandler(iAuthenticationFailureHandler)
                )
                .registeredClientRepository(registeredClientRepository)
                .authorizationService(authorizationService)
                .tokenGenerator(tokenGenerator)
                .tokenEndpoint(tokenEndpoint ->
                        tokenEndpoint
                                .accessTokenResponseHandler(new TokenResponseSuccessHandler(iSecurityUserExceptionMessageService))
                                .accessTokenRequestConverter(new CustomGrantAuthenticationConverter())
                                // found only Oauth2AuthenticationException is tossed.
                                .errorResponseHandler(iAuthenticationFailureHandler)
                                .authenticationProvider(new KnifeOauth2AuthenticationProvider(
                                        commonOAuth2AuthorizationCycle, conditionalDetailsService, oauth2AuthenticationHashCheckService,
                                        authorizationService, iSecurityUserExceptionMessageService
                                ))

                ).tokenIntrospectionEndpoint(tokenIntrospectEndpoint ->
                        tokenIntrospectEndpoint
                                .introspectionRequestConverter(httpServletRequest -> new Oauth2OpaqueTokenAuthenticationProvider(
                                        tokenIntrospector(
                                                authorizationService, conditionalDetailsService, iSecurityUserExceptionMessageService
                                        ),authorizationService, conditionalDetailsService
                                ).convert(httpServletRequest))
                                .authenticationProvider(new Oauth2OpaqueTokenAuthenticationProvider(
                                        tokenIntrospector(
                                                authorizationService, conditionalDetailsService, iSecurityUserExceptionMessageService
                                        ),authorizationService, conditionalDetailsService
                                )).errorResponseHandler(iAuthenticationFailureHandler));

        RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();

        http.csrf(AbstractHttpConfigurer::disable).securityMatcher(endpointsMatcher).authorizeHttpRequests(authorize ->
                authorize.anyRequest().authenticated());

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
                                                                 HandlerExceptionResolver handlerExceptionResolver, ISecurityUserExceptionMessageService iSecurityUserExceptionMessageService
    ) throws Exception {

        DefaultBearerTokenResolver resolver = new DefaultBearerTokenResolver();
        resolver.setAllowFormEncodedBodyParameter(true);

        http.csrf(AbstractHttpConfigurer::disable)
                .oauth2ResourceServer(oauth2 -> oauth2
                        .bearerTokenResolver(resolver)
                        .authenticationEntryPoint(new AuthenticationEntryPointToGlobalExceptionHandler(handlerExceptionResolver))
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

    @Bean
    @ConditionalOnMissingBean(AuthenticationFailureHandler.class)
    public AuthenticationFailureHandler iAuthenticationFailureHandler(ISecurityUserExceptionMessageService iSecurityUserExceptionMessageService) {
        return new DefaultAuthenticationFailureHandlerImpl(iSecurityUserExceptionMessageService);
    }
}
