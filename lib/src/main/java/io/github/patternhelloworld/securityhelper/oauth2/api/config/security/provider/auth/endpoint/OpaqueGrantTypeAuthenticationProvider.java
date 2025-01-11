package io.github.patternhelloworld.securityhelper.oauth2.api.config.security.provider.auth.endpoint;


import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.message.DefaultSecurityUserExceptionMessage;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.message.ISecurityUserExceptionMessageService;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.response.error.dto.EasyPlusErrorMessages;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.response.error.exception.EasyPlusOauth2AuthenticationException;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.serivce.CommonOAuth2AuthorizationSaver;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.serivce.DefaultOauth2AuthenticationHashCheckService;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.serivce.persistence.authorization.OAuth2AuthorizationServiceImpl;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.serivce.persistence.client.RegisteredClientRepositoryImpl;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.serivce.userdetail.ConditionalDetailsService;
import lombok.AllArgsConstructor;
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
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.util.HashMap;
import java.util.Map;

/*
 *    1) ROPC (grant_type=password, grant_type=refresh_token)
 *    2) Authorization Code flow
 *      - Get an authorization_code with username and password (grant_type=authorization_code)
 *      - Login with code received from the authorization code flow instead of username & password (grant_type=code)
 */
@AllArgsConstructor
public final class OpaqueGrantTypeAuthenticationProvider implements AuthenticationProvider {

    private final CommonOAuth2AuthorizationSaver commonOAuth2AuthorizationSaver;
    private final ConditionalDetailsService conditionalDetailsService;
    private final DefaultOauth2AuthenticationHashCheckService oauth2AuthenticationHashCheckService;
    private final OAuth2AuthorizationServiceImpl oAuth2AuthorizationService;
    private final ISecurityUserExceptionMessageService iSecurityUserExceptionMessageService;
    private final RegisteredClientRepositoryImpl registeredClientRepository;

    @Override
    public Authentication authenticate(Authentication authentication)
            throws EasyPlusOauth2AuthenticationException {

        try {
            if (authentication instanceof OAuth2ClientAuthenticationToken token) {

                // [NOTICE] If an incorrect client ID or Secret is detected, the OpaqueGrantTypeAccessTokenRequestConverter is not be invoked, which means there is NO mandatory client_id header parameter.
                // For reference, if an incorrect Basic header, such as base64(client_id:<--no secret here-->), is detected, the ClientSecretBasicAuthenticationConverter handles it directly and passes it to the AuthenticationFailureHandler.
                String clientId = token.getAdditionalParameters().getOrDefault("client_id", "").toString();
                if (clientId.isEmpty()) {
                    throw new EasyPlusOauth2AuthenticationException(EasyPlusErrorMessages.builder().message("Invalid Request. OpaqueGrantTypeAccessTokenRequestConverter was not invoked. This may indicate incorrect payloads or expired code or code_verifier.").userMessage(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_LOGIN_ERROR)).build());
                }

                Map<String, Object> modifiableAdditionalParameters = new HashMap<>(token.getAdditionalParameters());


                UserDetails userDetails;

                String grantType = modifiableAdditionalParameters.getOrDefault("grant_type", "").toString();
                if (grantType.isEmpty()) {
                    throw new EasyPlusOauth2AuthenticationException(EasyPlusErrorMessages.builder().message("No grant_type key found").userMessage(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_LOGIN_ERROR)).build());
                }

                String responseType = modifiableAdditionalParameters.getOrDefault("response_type", "").toString();

                switch (grantType) {
                    case "authorization_code" -> {
                        OAuth2Authorization oAuth2Authorization = oAuth2AuthorizationService.findByAuthorizationCode((String) modifiableAdditionalParameters.get("code"));
                        if (oAuth2Authorization == null) {
                            throw new EasyPlusOauth2AuthenticationException("authorization code not found");
                        }
                        userDetails = conditionalDetailsService.loadUserByUsername(oAuth2Authorization.getPrincipalName(), clientId);
                    }
                    case "password" -> {
                        userDetails = conditionalDetailsService.loadUserByUsername((String) modifiableAdditionalParameters.get("username"), clientId);
                        oauth2AuthenticationHashCheckService.validateUsernamePassword((String) modifiableAdditionalParameters.get("password"), userDetails);
                    }
                    case "refresh_token" -> {
                        OAuth2Authorization oAuth2Authorization = oAuth2AuthorizationService.findByToken((String) modifiableAdditionalParameters.get("refresh_token"), OAuth2TokenType.REFRESH_TOKEN);
                        if (oAuth2Authorization != null) {
                            userDetails = conditionalDetailsService.loadUserByUsername(oAuth2Authorization.getPrincipalName(), clientId);
                        } else {
                            throw new EasyPlusOauth2AuthenticationException(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_LOGIN_ERROR));
                        }
                    }
                    default -> throw new EasyPlusOauth2AuthenticationException(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_WRONG_GRANT_TYPE));
                }

                // Create tokens at this point
                OAuth2Authorization oAuth2Authorization = commonOAuth2AuthorizationSaver.save(userDetails, new AuthorizationGrantType(modifiableAdditionalParameters.get("grant_type").toString()), clientId, modifiableAdditionalParameters);

                RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);
                if (registeredClient == null) {
                    throw new EasyPlusOauth2AuthenticationException(EasyPlusErrorMessages.builder().message("client_id NOT found in DB").userMessage(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_LOGIN_ERROR)).build());
                }

                if (responseType.equals(OAuth2ParameterNames.CODE)) {
                    // [IMPORTANT] To return the "code" not "access_token". Check "AuthenticationSuccessHandler".
                    modifiableAdditionalParameters.put("code", oAuth2Authorization.getToken(OAuth2AuthorizationCode.class).getToken().getTokenValue());
                }

                authentication.setAuthenticated(true);
                return new OAuth2AccessTokenAuthenticationToken(
                        registeredClient,
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
}
