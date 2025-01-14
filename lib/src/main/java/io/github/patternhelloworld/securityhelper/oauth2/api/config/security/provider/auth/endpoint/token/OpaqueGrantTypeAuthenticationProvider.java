package io.github.patternhelloworld.securityhelper.oauth2.api.config.security.provider.auth.endpoint.token;


import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.message.DefaultSecurityUserExceptionMessage;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.message.ISecurityUserExceptionMessageService;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.response.error.dto.EasyPlusErrorMessages;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.response.error.exception.EasyPlusOauth2AuthenticationException;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.serivce.CommonOAuth2AuthorizationSaver;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.serivce.DefaultOauth2AuthenticationHashCheckService;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.serivce.persistence.authorization.OAuth2AuthorizationServiceImpl;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.serivce.userdetail.ConditionalDetailsService;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.validator.endpoint.token.CodeValidationResult;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.util.Assert;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

/*
 *    1) ROPC (grant_type=password, grant_type=refresh_token)
 *    2) Authorization Code flow
 *      - Get an authorization_code with username and password (grant_type=authorization_code)
 *      - Login with code received from the authorization code flow instead of username & password (grant_type=code)
 */
@RequiredArgsConstructor
public final class OpaqueGrantTypeAuthenticationProvider implements AuthenticationProvider {

    private static final Logger logger = LoggerFactory.getLogger(OpaqueGrantTypeAuthenticationProvider.class);

    private Function<Map<String, Object>, CodeValidationResult> authenticationValidator;

    private final CommonOAuth2AuthorizationSaver commonOAuth2AuthorizationSaver;
    private final ConditionalDetailsService conditionalDetailsService;
    private final DefaultOauth2AuthenticationHashCheckService oauth2AuthenticationHashCheckService;
    private final OAuth2AuthorizationServiceImpl oAuth2AuthorizationService;
    private final ISecurityUserExceptionMessageService iSecurityUserExceptionMessageService;

    @Override
    public Authentication authenticate(Authentication authentication)
            throws EasyPlusOauth2AuthenticationException {

        try {
            if (authentication instanceof OAuth2ClientAuthenticationToken token) {

                Map<String, Object> modifiableAdditionalParameters = new HashMap<>(token.getAdditionalParameters());
                CodeValidationResult codeValidationResult = this.authenticationValidator.apply(modifiableAdditionalParameters);

                UserDetails userDetails;
                switch (codeValidationResult.getGrantType()) {
                    case "authorization_code" -> {
                        OAuth2Authorization oAuth2Authorization = oAuth2AuthorizationService.findByAuthorizationCode(codeValidationResult.getCode());
                        if (oAuth2Authorization == null) {
                            throw new EasyPlusOauth2AuthenticationException(EasyPlusErrorMessages.builder().message("No user info found for the authorization code").userMessage(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_LOGIN_FAILURE)).build());
                        }
                        userDetails = conditionalDetailsService.loadUserByUsername(oAuth2Authorization.getPrincipalName(), codeValidationResult.getClientId());
                    }
                    case "password" -> {
                        userDetails = conditionalDetailsService.loadUserByUsername((String) modifiableAdditionalParameters.get("username"), codeValidationResult.getClientId());
                        oauth2AuthenticationHashCheckService.validateUsernamePassword((String) modifiableAdditionalParameters.get("password"), userDetails);
                    }
                    case "refresh_token" -> {
                        OAuth2Authorization oAuth2Authorization = oAuth2AuthorizationService.findByToken((String) modifiableAdditionalParameters.get("refresh_token"), OAuth2TokenType.REFRESH_TOKEN);
                        if (oAuth2Authorization != null) {
                            userDetails = conditionalDetailsService.loadUserByUsername(oAuth2Authorization.getPrincipalName(), codeValidationResult.getClientId());
                        } else {
                            throw new EasyPlusOauth2AuthenticationException(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_LOGIN_ERROR));
                        }
                    }
                    default -> throw new EasyPlusOauth2AuthenticationException(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_WRONG_GRANT_TYPE));
                }

                // Create tokens at this point
                OAuth2Authorization oAuth2Authorization = commonOAuth2AuthorizationSaver.save(userDetails, new AuthorizationGrantType(modifiableAdditionalParameters.get("grant_type").toString()), codeValidationResult.getClientId(), modifiableAdditionalParameters);

                if (codeValidationResult.getResponseType() != null && codeValidationResult.getResponseType().equals(OAuth2ParameterNames.CODE)) {
                    // [IMPORTANT] To return the "code" not "access_token". Check "AuthenticationSuccessHandler".
                    modifiableAdditionalParameters.put("code", oAuth2Authorization.getToken(OAuth2AuthorizationCode.class).getToken().getTokenValue());
                }

                authentication.setAuthenticated(true);
                return new OAuth2AccessTokenAuthenticationToken(
                        codeValidationResult.getRegisteredClient(),
                        getAuthenticatedClientElseThrowInvalidClient(authentication),
                        oAuth2Authorization.getAccessToken().getToken(),
                        oAuth2Authorization.getRefreshToken() != null ? oAuth2Authorization.getRefreshToken().getToken() : null,
                        modifiableAdditionalParameters
                );
            } else {
                throw new EasyPlusOauth2AuthenticationException();
            }
        } catch (UsernameNotFoundException e) {
            throw new EasyPlusOauth2AuthenticationException(EasyPlusErrorMessages.builder().message(e.getMessage()).userMessage(e.getMessage()).build(), e);
        } catch (EasyPlusOauth2AuthenticationException e) {
            throw e;
        } catch (Exception e) {
            throw new EasyPlusOauth2AuthenticationException(EasyPlusErrorMessages.builder().message(e.getMessage()).userMessage(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_LOGIN_ERROR)).build(), e);
        }

    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication);
    }

    private OAuth2ClientAuthenticationToken getAuthenticatedClientElseThrowInvalidClient(Authentication authentication) {
        OAuth2ClientAuthenticationToken clientPrincipal = null;
        if (authentication instanceof OAuth2ClientAuthenticationToken) {
            clientPrincipal = (OAuth2ClientAuthenticationToken) authentication;
        }
        if (clientPrincipal != null && clientPrincipal.isAuthenticated()) {
            return clientPrincipal;
        }
        throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT));
    }

    public void setAuthenticationValidator(Function<Map<String, Object>, CodeValidationResult> authenticationValidator) {
        Assert.notNull(authenticationValidator, "authenticationValidator cannot be null");
        this.authenticationValidator = authenticationValidator;
    }
}
