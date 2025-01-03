package com.patternknife.securityhelper.oauth2.client.config.securityimpl.introspector;

import io.github.patternknife.securityhelper.oauth2.api.config.security.message.ISecurityUserExceptionMessageService;
import io.github.patternknife.securityhelper.oauth2.api.config.security.response.error.exception.KnifeOauth2AuthenticationException;
import io.github.patternknife.securityhelper.oauth2.api.config.security.serivce.persistence.authorization.OAuth2AuthorizationServiceImpl;
import io.github.patternknife.securityhelper.oauth2.api.config.security.serivce.userdetail.ConditionalDetailsService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.server.resource.introspection.SpringOpaqueTokenIntrospector;
import org.springframework.stereotype.Component;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.NimbusOpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;

@Component
public class CustomDefaultResourceServerTokenIntrospector implements OpaqueTokenIntrospector {

    private final OpaqueTokenIntrospector delegate;

    public CustomDefaultResourceServerTokenIntrospector(
            @Value("${security.oauth2.introspection.uri}") String introspectionUri,
            @Value("${security.oauth2.introspection.client-id}") String clientId,
            @Value("${security.oauth2.introspection.client-secret}") String clientSecret) {
        this.delegate = new SpringOpaqueTokenIntrospector(introspectionUri, clientId, clientSecret);
    }

    @Override
    public OAuth2AuthenticatedPrincipal introspect(String token) {
        try {
            return delegate.introspect(token);
        } catch (Exception e) {
            throw new KnifeOauth2AuthenticationException(e.getMessage());
        }
    }
}

