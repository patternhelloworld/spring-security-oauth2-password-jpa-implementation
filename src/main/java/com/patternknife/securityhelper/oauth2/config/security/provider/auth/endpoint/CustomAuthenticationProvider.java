package com.patternknife.securityhelper.oauth2.config.security.provider.auth.endpoint;

import com.patternknife.securityhelper.oauth2.config.response.error.exception.auth.OtpValueUnauthorizedException;
import com.patternknife.securityhelper.oauth2.config.response.error.exception.auth.UnauthenticatedException;
import com.patternknife.securityhelper.oauth2.config.security.OAuth2ClientCachedInfo;
import com.patternknife.securityhelper.oauth2.config.security.principal.AccessTokenUserInfo;
import com.patternknife.securityhelper.oauth2.config.security.serivce.CommonOAuth2AuthorizationCycle;
import com.patternknife.securityhelper.oauth2.config.security.serivce.OAuth2AuthorizationServiceImpl;
import com.patternknife.securityhelper.oauth2.config.security.serivce.Oauth2AuthenticationService;
import com.patternknife.securityhelper.oauth2.config.security.serivce.userdetail.ConditionalDetailsService;
import com.patternknife.securityhelper.oauth2.config.security.token.CustomGrantAuthenticationToken;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.io.Serializable;
import java.util.Objects;


@AllArgsConstructor
public class CustomAuthenticationProvider implements AuthenticationProvider, Serializable {

    private final CommonOAuth2AuthorizationCycle commonOAuth2AuthorizationCycle;
    private final ConditionalDetailsService conditionalDetailsService;
    private final Oauth2AuthenticationService oauth2AuthenticationService;
    private final OAuth2AuthorizationServiceImpl oAuth2AuthorizationService;

    @Override
    public Authentication authenticate(Authentication authentication)
            throws AuthenticationException, OtpValueUnauthorizedException {

        if(authentication instanceof CustomGrantAuthenticationToken customGrantAuthenticationToken){

            OAuth2ClientAuthenticationToken oAuth2ClientAuthenticationToken = getAuthenticatedClientElseThrowInvalidClient(customGrantAuthenticationToken);

            String clientId = Objects.requireNonNull(oAuth2ClientAuthenticationToken.getRegisteredClient()).getClientId();

            UserDetails userDetails;
            if(((String)customGrantAuthenticationToken.getAdditionalParameters().get("grant_type")).equals(AuthorizationGrantType.PASSWORD.getValue())){
                userDetails = conditionalDetailsService.loadUserByUsername((String)customGrantAuthenticationToken.getAdditionalParameters().get("username"), clientId);

                if(clientId.equals(OAuth2ClientCachedInfo.ADMIN_CLIENT_ID.getValue())){
                    oauth2AuthenticationService.validateOtpValue((String)customGrantAuthenticationToken.getAdditionalParameters().get("otp_value"),((AccessTokenUserInfo) userDetails).getAdditionalAccessTokenUserInfo().getOtpSecretKey());
                }

                oauth2AuthenticationService.validatePassword((String)customGrantAuthenticationToken.getAdditionalParameters().get("password"), userDetails);

            }else if(((String)customGrantAuthenticationToken.getAdditionalParameters().get("grant_type")).equals(AuthorizationGrantType.REFRESH_TOKEN.getValue())){
                OAuth2Authorization oAuth2Authorization = oAuth2AuthorizationService.findByToken((String)customGrantAuthenticationToken.getAdditionalParameters().get("refresh_token"), OAuth2TokenType.REFRESH_TOKEN);
                if(oAuth2Authorization != null) {
                    userDetails = conditionalDetailsService.loadUserByUsername(oAuth2Authorization.getPrincipalName(), clientId);
                }else{
                    throw new UnauthenticatedException("해당 토큰으로 부터 인증 정보를 찾을 수 없습니다.");
                }
            }else{
                throw new IllegalStateException("잘못된 Grant Type 입니다.");
            }

            OAuth2Authorization oAuth2Authorization = commonOAuth2AuthorizationCycle.run(userDetails, ((CustomGrantAuthenticationToken) authentication).getGrantType(), clientId, ((CustomGrantAuthenticationToken) authentication).getAdditionalParameters());

            RegisteredClient registeredClient = oAuth2ClientAuthenticationToken.getRegisteredClient();


            return new OAuth2AccessTokenAuthenticationToken(
                    registeredClient,
                    getAuthenticatedClientElseThrowInvalidClient(authentication),
                    oAuth2Authorization.getAccessToken().getToken(),
                    oAuth2Authorization.getRefreshToken() != null ? oAuth2Authorization.getRefreshToken().getToken() : null,
                    ((CustomGrantAuthenticationToken) authentication).getAdditionalParameters()
            );
        }else{
            throw new UnauthenticatedException();
        }

    }

    @Override
    public boolean supports(Class<?> authentication) {
        return CustomGrantAuthenticationToken.class.isAssignableFrom(authentication);
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
