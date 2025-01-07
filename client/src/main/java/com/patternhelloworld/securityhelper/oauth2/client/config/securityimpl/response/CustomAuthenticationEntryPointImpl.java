package com.patternhelloworld.securityhelper.oauth2.client.config.securityimpl.response;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.web.servlet.HandlerExceptionResolver;

import java.io.IOException;

/*
 *
 * The functionality is already implemented in the library's
 * 'authentication.resource.response.security.config.io.github.patternhelloworld.securityhelper.oauth2.api.DefaultAuthenticationEntryPoint'.
 *
 * Create this class only if you need a custom implementation that differs from the default.
 */
@Configuration
@RequiredArgsConstructor
public class CustomAuthenticationEntryPointImpl implements AuthenticationEntryPoint {

    @Qualifier("handlerExceptionResolver")
    private final HandlerExceptionResolver resolver;

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException ex) throws IOException {
        resolver.resolveException(request, response, null, ex);
    }
}