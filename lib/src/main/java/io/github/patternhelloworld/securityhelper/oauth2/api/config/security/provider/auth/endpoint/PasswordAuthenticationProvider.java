package io.github.patternhelloworld.securityhelper.oauth2.api.config.security.provider.auth.endpoint;


import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.response.error.exception.EasyPlusOauth2AuthenticationException;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.serivce.userdetail.ConditionalDetailsService;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.response.error.dto.EasyPlusErrorMessages;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.message.DefaultSecurityUserExceptionMessage;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.message.ISecurityUserExceptionMessageService;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.serivce.CommonOAuth2AuthorizationSaver;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.serivce.DefaultOauth2AuthenticationHashCheckService;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.serivce.persistence.authorization.OAuth2AuthorizationServiceImpl;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.token.EasyPlusGrantAuthenticationToken;
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

import java.util.Objects;


/*
 *    1) ROPC (grant_type=password, grant_type=refresh_token)
 *    2) Authorization Code flow
 *      - Get an authorization_code with username and password (grant_type=authorization_code)
 *      - Login with code received from the authorization code flow instead of username & password (grant_type=code)
 * */
@AllArgsConstructor
public final class PasswordAuthenticationProvider implements AuthenticationProvider {

    private final CommonOAuth2AuthorizationSaver commonOAuth2AuthorizationSaver;
    private final ConditionalDetailsService conditionalDetailsService;
    private final DefaultOauth2AuthenticationHashCheckService oauth2AuthenticationHashCheckService;
    private final OAuth2AuthorizationServiceImpl oAuth2AuthorizationService;
    private final ISecurityUserExceptionMessageService iSecurityUserExceptionMessageService;

    @Override
    public Authentication authenticate(Authentication authentication)
            throws EasyPlusOauth2AuthenticationException {

        try {
            if (authentication instanceof EasyPlusGrantAuthenticationToken easyPlusGrantAuthenticationToken) {

                OAuth2ClientAuthenticationToken oAuth2ClientAuthenticationToken = getAuthenticatedClientElseThrowInvalidClient(easyPlusGrantAuthenticationToken);

                String clientId = Objects.requireNonNull(oAuth2ClientAuthenticationToken.getRegisteredClient()).getClientId();

                UserDetails userDetails;

                /*
                *   To only get authorization_code, NOT access_token or refresh_token
                * */
                if (((String) easyPlusGrantAuthenticationToken.getAdditionalParameters().get("grant_type")).equals(AuthorizationGrantType.AUTHORIZATION_CODE.getValue())) {

                    userDetails = conditionalDetailsService.loadUserByUsername((String) easyPlusGrantAuthenticationToken.getAdditionalParameters().get("username"), clientId);

                    oauth2AuthenticationHashCheckService.validateUsernamePassword((String) easyPlusGrantAuthenticationToken.getAdditionalParameters().get("password"), userDetails);

                    OAuth2Authorization oAuth2Authorization = commonOAuth2AuthorizationSaver.save(userDetails, ((EasyPlusGrantAuthenticationToken) authentication).getGrantType(), clientId, ((EasyPlusGrantAuthenticationToken) authentication).getAdditionalParameters(), null);

                    RegisteredClient registeredClient = oAuth2ClientAuthenticationToken.getRegisteredClient();

                    ((EasyPlusGrantAuthenticationToken) authentication).getAdditionalParameters().put("authorization_code", oAuth2Authorization.getToken(OAuth2AuthorizationCode.class).getToken().getTokenValue());

                    return new OAuth2AccessTokenAuthenticationToken(
                            registeredClient,
                            getAuthenticatedClientElseThrowInvalidClient(authentication),
                            oAuth2Authorization.getAccessToken().getToken(),
                            oAuth2Authorization.getRefreshToken() != null ? oAuth2Authorization.getRefreshToken().getToken() : null,
                            ((EasyPlusGrantAuthenticationToken) authentication).getAdditionalParameters()
                    );

                }
                /*
                 *   To get access_token & refresh_token
                 * */
                else if (((String) easyPlusGrantAuthenticationToken.getAdditionalParameters().get("grant_type")).equals(OAuth2ParameterNames.CODE)) {

                    OAuth2Authorization oAuth2Authorization = oAuth2AuthorizationService.findByAuthorizationCode((String) easyPlusGrantAuthenticationToken.getAdditionalParameters().get("code"));
                    if(oAuth2Authorization == null){
                        throw new EasyPlusOauth2AuthenticationException("authorization code not found");
                    }

                    userDetails = conditionalDetailsService.loadUserByUsername(oAuth2Authorization.getPrincipalName(), clientId);


                }
                /*
                 *   To get access_token & refresh_token
                 * */
                else if (((String) easyPlusGrantAuthenticationToken.getAdditionalParameters().get("grant_type")).equals(AuthorizationGrantType.PASSWORD.getValue())) {

                    userDetails = conditionalDetailsService.loadUserByUsername((String) easyPlusGrantAuthenticationToken.getAdditionalParameters().get("username"), clientId);

                    oauth2AuthenticationHashCheckService.validateUsernamePassword((String) easyPlusGrantAuthenticationToken.getAdditionalParameters().get("password"), userDetails);

                }
                /*
                 *   To exchange an old access_token with a new one
                 * */
                else if (((String) easyPlusGrantAuthenticationToken.getAdditionalParameters().get("grant_type")).equals(AuthorizationGrantType.REFRESH_TOKEN.getValue())) {
                    OAuth2Authorization oAuth2Authorization = oAuth2AuthorizationService.findByToken((String) easyPlusGrantAuthenticationToken.getAdditionalParameters().get("refresh_token"), OAuth2TokenType.REFRESH_TOKEN);
                    if (oAuth2Authorization != null) {
                        userDetails = conditionalDetailsService.loadUserByUsername(oAuth2Authorization.getPrincipalName(), clientId);
                    } else {
                        throw new EasyPlusOauth2AuthenticationException(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_LOGIN_ERROR));
                    }
                } else {
                    throw new EasyPlusOauth2AuthenticationException(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_WRONG_GRANT_TYPE));
                }


                OAuth2Authorization oAuth2Authorization = commonOAuth2AuthorizationSaver.save(userDetails, ((EasyPlusGrantAuthenticationToken) authentication).getGrantType(), clientId, ((EasyPlusGrantAuthenticationToken) authentication).getAdditionalParameters(), null);

                RegisteredClient registeredClient = oAuth2ClientAuthenticationToken.getRegisteredClient();


                return new OAuth2AccessTokenAuthenticationToken(
                        registeredClient,
                        getAuthenticatedClientElseThrowInvalidClient(authentication),
                        oAuth2Authorization.getAccessToken().getToken(),
                        oAuth2Authorization.getRefreshToken() != null ? oAuth2Authorization.getRefreshToken().getToken() : null,
                        easyPlusGrantAuthenticationToken.getAdditionalParameters()
                );
            } else {
                throw new EasyPlusOauth2AuthenticationException();
            }
        }catch (UsernameNotFoundException e){
            throw new EasyPlusOauth2AuthenticationException(EasyPlusErrorMessages.builder().message(e.getMessage()).userMessage(e.getMessage()).build());
        }catch (EasyPlusOauth2AuthenticationException e){
            throw e;
        }  catch (Exception e){
           throw e;
        }

    }

    @Override
    public boolean supports(Class<?> authentication) {
        return EasyPlusGrantAuthenticationToken.class.isAssignableFrom(authentication);
    }

    private OAuth2ClientAuthenticationToken getAuthenticatedClientElseThrowInvalidClient(Authentication authentication) {
        OAuth2ClientAuthenticationToken clientPrincipal = null;
        if (authentication.getPrincipal() instanceof OAuth2ClientAuthenticationToken) {
            clientPrincipal = (OAuth2ClientAuthenticationToken) authentication.getPrincipal();
        }
        if (clientPrincipal != null && clientPrincipal.isAuthenticated()) {
            return clientPrincipal;
        }
        throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT));
    }

}
