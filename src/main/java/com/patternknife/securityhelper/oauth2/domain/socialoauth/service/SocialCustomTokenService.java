package com.patternknife.securityhelper.oauth2.domain.socialoauth.service;

import com.patternknife.securityhelper.oauth2.config.logger.module.NonStopErrorLogConfig;
import com.patternknife.securityhelper.oauth2.config.response.error.exception.auth.NoSocialRegisteredException;
import com.patternknife.securityhelper.oauth2.config.security.OAuth2ClientCachedInfo;
import com.patternknife.securityhelper.oauth2.config.security.serivce.CommonOAuth2AuthorizationCycle;
import com.patternknife.securityhelper.oauth2.config.security.serivce.userdetail.CustomerDetailsService;
import com.patternknife.securityhelper.oauth2.config.security.util.SecurityUtil;
import com.patternknife.securityhelper.oauth2.domain.customer.entity.Customer;
import com.patternknife.securityhelper.oauth2.domain.socialoauth.dto.SpringSecuritySocialOauthDTO;
import io.netty.util.internal.StringUtil;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;


@Service
@RequiredArgsConstructor
public class SocialCustomTokenService {

    private static final Logger logger = LoggerFactory.getLogger(NonStopErrorLogConfig.class);

    private final CustomerDetailsService customerDetailsService;
    private final CommonOAuth2AuthorizationCycle oAuth2AuthorizationCycle;


    public SpringSecuritySocialOauthDTO.TokenResponse createAccessToken(Customer customer, String clientId) {

        if(customer == null || customer.getIdName() == null){
            // 기존에 소셜 로그인 가입이 안되어 있다.
            // TO DO. 앱에서 특정 코드가 아닌 이 메시지로 분기를 타는데, 이를 약속된 코드로 변경해야 함
            throw new NoSocialRegisteredException("인증 화면으로 연결됩니다.");

        }else{

            /*
             *   Entering here means that you are already registered with a KAKAO, NAVER, GOOGLE, or APPLE ID, and your account has NOT been deleted or suspended.
             * */

            UserDetails userDetails = customerDetailsService.loadUserByUsername(customer.getIdName());

            Boolean justNowCreated = false;

            HttpServletRequest request =
                    ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();

            OAuth2Authorization oAuth2Authorization = oAuth2AuthorizationCycle.run(userDetails,
                    new AuthorizationGrantType(AuthorizationGrantType.PASSWORD.getValue()),
                    clientId, SecurityUtil.getTokenUsingSecurityAdditionalParametersSocial(request, customer.getIdName()));


            Instant now = Instant.now();
            Instant expiresAt = oAuth2Authorization.getAccessToken().getToken().getExpiresAt();
            int accessTokenRemainingSeconds = Math.toIntExact(Duration.between(now, expiresAt).getSeconds());


            return new SpringSecuritySocialOauthDTO.TokenResponse(
                    "Bearer",  oAuth2Authorization.getAccessToken().getToken().getTokenValue(), Objects.requireNonNull(oAuth2Authorization.getRefreshToken()).getToken().getTokenValue(),
                    accessTokenRemainingSeconds,
                    String.join(" ", OAuth2ClientCachedInfo.CUSTOMER_CLIENT_ID.getScope()), justNowCreated, !StringUtil.isNullOrEmpty(userDetails.getPassword()));
        }

    }


    public String createAccessTokenToRedirect(Customer customer, String clientId, String hostName, String scheme, String idToken) {

        try {
            SpringSecuritySocialOauthDTO.TokenResponse tokenResponse = createAccessToken(customer, clientId);
            return "redirect:" + scheme + "://" + hostName + ":3100/auth/token-info/me?" + createTokenResponseQueryString(tokenResponse);
        } catch (NoSocialRegisteredException ex) {
            return "redirect:" + scheme + "://" + hostName + ":3100/auth/kt-pass/me?idToken=" + idToken;
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    private String createTokenResponseQueryString(SpringSecuritySocialOauthDTO.TokenResponse tokenResponse) throws UnsupportedEncodingException {
        return "token_type=" + URLEncoder.encode(tokenResponse.getToken_type(), StandardCharsets.UTF_8.name()) +
                "&access_token=" + URLEncoder.encode(tokenResponse.getAccess_token(), StandardCharsets.UTF_8.name()) +
                "&refresh_token=" + URLEncoder.encode(tokenResponse.getRefresh_token(), StandardCharsets.UTF_8.name()) +
                "&expires_in=" + tokenResponse.getExpires_in() +
                "&scope=" + URLEncoder.encode(tokenResponse.getScope(), StandardCharsets.UTF_8.name()) +
                "&just_now_created=" + tokenResponse.getJust_now_created() +
                "&password_registered=" + tokenResponse.getPassword_registered();
    }

}
