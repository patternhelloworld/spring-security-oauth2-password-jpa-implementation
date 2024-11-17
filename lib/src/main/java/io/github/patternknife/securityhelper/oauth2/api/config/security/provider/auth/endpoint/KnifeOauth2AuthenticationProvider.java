package io.github.patternknife.securityhelper.oauth2.api.config.security.provider.auth.endpoint;


import io.github.patternknife.securityhelper.oauth2.api.config.security.response.error.exception.KnifeOauth2AuthenticationException;
import io.github.patternknife.securityhelper.oauth2.api.config.security.serivce.userdetail.ConditionalDetailsService;
import io.github.patternknife.securityhelper.oauth2.api.config.security.response.error.dto.ErrorMessages;
import io.github.patternknife.securityhelper.oauth2.api.config.security.message.DefaultSecurityUserExceptionMessage;
import io.github.patternknife.securityhelper.oauth2.api.config.security.message.ISecurityUserExceptionMessageService;
import io.github.patternknife.securityhelper.oauth2.api.config.security.serivce.CommonOAuth2AuthorizationSaver;
import io.github.patternknife.securityhelper.oauth2.api.config.security.serivce.DefaultOauth2AuthenticationHashCheckService;
import io.github.patternknife.securityhelper.oauth2.api.config.security.serivce.persistence.authorization.OAuth2AuthorizationServiceImpl;
import io.github.patternknife.securityhelper.oauth2.api.config.security.token.KnifeGrantAuthenticationToken;
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
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken;
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
public final class KnifeOauth2AuthenticationProvider implements AuthenticationProvider {

    private final CommonOAuth2AuthorizationSaver commonOAuth2AuthorizationSaver;
    private final ConditionalDetailsService conditionalDetailsService;
    private final DefaultOauth2AuthenticationHashCheckService oauth2AuthenticationHashCheckService;
    private final OAuth2AuthorizationServiceImpl oAuth2AuthorizationService;
    private final ISecurityUserExceptionMessageService iSecurityUserExceptionMessageService;

    @Override
    public Authentication authenticate(Authentication authentication)
            throws KnifeOauth2AuthenticationException {

        try {
            if (authentication instanceof KnifeGrantAuthenticationToken knifeGrantAuthenticationToken) {

                OAuth2ClientAuthenticationToken oAuth2ClientAuthenticationToken = getAuthenticatedClientElseThrowInvalidClient(knifeGrantAuthenticationToken);

                String clientId = Objects.requireNonNull(oAuth2ClientAuthenticationToken.getRegisteredClient()).getClientId();

                UserDetails userDetails;

                /*
                *   To only get authorization_code, NOT access_token or refresh_token
                * */
                if (((String) knifeGrantAuthenticationToken.getAdditionalParameters().get("grant_type")).equals(AuthorizationGrantType.AUTHORIZATION_CODE.getValue())) {

                    userDetails = conditionalDetailsService.loadUserByUsername((String) knifeGrantAuthenticationToken.getAdditionalParameters().get("username"), clientId);

                    oauth2AuthenticationHashCheckService.validateUsernamePassword((String) knifeGrantAuthenticationToken.getAdditionalParameters().get("password"), userDetails);

                    OAuth2Authorization oAuth2Authorization = commonOAuth2AuthorizationSaver.save(userDetails, ((KnifeGrantAuthenticationToken) authentication).getGrantType(), clientId, ((KnifeGrantAuthenticationToken) authentication).getAdditionalParameters(), null);

                    RegisteredClient registeredClient = oAuth2ClientAuthenticationToken.getRegisteredClient();

                    ((KnifeGrantAuthenticationToken) authentication).getAdditionalParameters().put("authorization_code", oAuth2Authorization.getToken(OAuth2AuthorizationCode.class).getToken().getTokenValue());

                    return new OAuth2AccessTokenAuthenticationToken(
                            registeredClient,
                            getAuthenticatedClientElseThrowInvalidClient(authentication),
                            oAuth2Authorization.getAccessToken().getToken(),
                            oAuth2Authorization.getRefreshToken() != null ? oAuth2Authorization.getRefreshToken().getToken() : null,
                            ((KnifeGrantAuthenticationToken) authentication).getAdditionalParameters()
                    );

                }
                /*
                 *   To get access_token & refresh_token
                 * */
                else if (((String) knifeGrantAuthenticationToken.getAdditionalParameters().get("grant_type")).equals(OAuth2ParameterNames.CODE)) {

                    OAuth2Authorization oAuth2Authorization = oAuth2AuthorizationService.findByAuthorizationCode((String) knifeGrantAuthenticationToken.getAdditionalParameters().get("code"));
                    if(oAuth2Authorization == null){
                        throw new KnifeOauth2AuthenticationException("authorization code not found");
                    }

                    userDetails = conditionalDetailsService.loadUserByUsername(oAuth2Authorization.getPrincipalName(), clientId);


                }
                /*
                 *   To get access_token & refresh_token
                 * */
                else if (((String) knifeGrantAuthenticationToken.getAdditionalParameters().get("grant_type")).equals(AuthorizationGrantType.PASSWORD.getValue())) {

                    userDetails = conditionalDetailsService.loadUserByUsername((String) knifeGrantAuthenticationToken.getAdditionalParameters().get("username"), clientId);

                    oauth2AuthenticationHashCheckService.validateUsernamePassword((String) knifeGrantAuthenticationToken.getAdditionalParameters().get("password"), userDetails);

                }
                /*
                 *   To exchange an old access_token with a new one
                 * */
                else if (((String) knifeGrantAuthenticationToken.getAdditionalParameters().get("grant_type")).equals(AuthorizationGrantType.REFRESH_TOKEN.getValue())) {
                    OAuth2Authorization oAuth2Authorization = oAuth2AuthorizationService.findByToken((String) knifeGrantAuthenticationToken.getAdditionalParameters().get("refresh_token"), OAuth2TokenType.REFRESH_TOKEN);
                    if (oAuth2Authorization != null) {
                        userDetails = conditionalDetailsService.loadUserByUsername(oAuth2Authorization.getPrincipalName(), clientId);
                    } else {
                        throw new KnifeOauth2AuthenticationException(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_LOGIN_ERROR));
                    }
                } else {
                    throw new KnifeOauth2AuthenticationException(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_WRONG_GRANT_TYPE));
                }


                OAuth2Authorization oAuth2Authorization = commonOAuth2AuthorizationSaver.save(userDetails, ((KnifeGrantAuthenticationToken) authentication).getGrantType(), clientId, ((KnifeGrantAuthenticationToken) authentication).getAdditionalParameters(), null);

                RegisteredClient registeredClient = oAuth2ClientAuthenticationToken.getRegisteredClient();


                return new OAuth2AccessTokenAuthenticationToken(
                        registeredClient,
                        getAuthenticatedClientElseThrowInvalidClient(authentication),
                        oAuth2Authorization.getAccessToken().getToken(),
                        oAuth2Authorization.getRefreshToken() != null ? oAuth2Authorization.getRefreshToken().getToken() : null,
                        ((KnifeGrantAuthenticationToken) authentication).getAdditionalParameters()
                );
            } else {
                throw new KnifeOauth2AuthenticationException();
            }
        }catch (UsernameNotFoundException e){
            throw new KnifeOauth2AuthenticationException(ErrorMessages.builder().message(e.getMessage()).userMessage(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_LOGIN_FAILURE)).build());
        }catch (KnifeOauth2AuthenticationException e){
            throw e;
        }  catch (Exception e){
           throw new KnifeOauth2AuthenticationException(ErrorMessages.builder().message(e.getMessage()).userMessage(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_LOGIN_ERROR)).build());
        }

    }

    @Override
    public boolean supports(Class<?> authentication) {
        return KnifeGrantAuthenticationToken.class.isAssignableFrom(authentication);
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
