package com.patternknife.securityhelper.oauth2.domain.socialoauth.service;

import com.patternknife.securityhelper.oauth2.config.response.error.exception.auth.AlreadySocialRegisteredException;
import com.patternknife.securityhelper.oauth2.config.response.error.exception.auth.SocialEmailNotProvidedException;
import com.patternknife.securityhelper.oauth2.config.response.error.exception.auth.SocialUnauthorizedException;
import com.patternknife.securityhelper.oauth2.domain.customer.dao.CustomerRepository;
import com.patternknife.securityhelper.oauth2.domain.customer.dao.CustomerRepositorySupport;
import com.patternknife.securityhelper.oauth2.domain.customer.entity.Customer;
import com.patternknife.securityhelper.oauth2.domain.socialoauth.bo.GoogleAuth;
import com.patternknife.securityhelper.oauth2.domain.socialoauth.bo.KakaoAuth;
import com.patternknife.securityhelper.oauth2.domain.socialoauth.bo.NaverAuth;
import com.patternknife.securityhelper.oauth2.domain.socialoauth.bo.SocialOauthMessageCreator;
import com.patternknife.securityhelper.oauth2.domain.socialoauth.dto.SocialVendorOauthDTO;
import com.patternknife.securityhelper.oauth2.domain.socialoauth.dto.SpringSecuritySocialOauthDTO;
import com.patternknife.securityhelper.oauth2.domain.socialoauth.dto.apple.AppleUserInfo;
import com.patternknife.securityhelper.oauth2.domain.socialoauth.service.apple.AppleService;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;


@Service
public class SocialOauthService {

    private final RestTemplate kaKaoUserInfoTemplate;
    private final RestTemplate naverUserInfoTemplate;
    private final RestTemplate googleUserInfoTemplate;
    
    private final SocialCustomTokenService socialCustomTokenService;

    private final CustomerRepository customerRepository;
    private final CustomerRepositorySupport customerRepositorySupport;

    private final AppleService appleService;


    @Value("${app.oauth2.appUser.clientId}")
    private String appUserClientId;

    public SocialOauthService(@Qualifier("kaKaoOpenApiTemplate") RestTemplate kaKaoUserInfoTemplate,
                              @Qualifier("naverOpenApiTemplate") RestTemplate naverUserInfoTemplate,
                              @Qualifier("googleOpenApiTemplate") RestTemplate googleUserInfoTemplate,
                              SocialCustomTokenService socialCustomTokenService,
                              CustomerRepository customerRepository,
                              CustomerRepositorySupport customerRepositorySupport,
                                AppleService appleService) {
        this.kaKaoUserInfoTemplate = kaKaoUserInfoTemplate;
        this.naverUserInfoTemplate = naverUserInfoTemplate;
        this.googleUserInfoTemplate = googleUserInfoTemplate;

        this.socialCustomTokenService = socialCustomTokenService;
        this.customerRepository = customerRepository;
        this.customerRepositorySupport = customerRepositorySupport;

        this.appleService = appleService;
    }

    public SpringSecuritySocialOauthDTO.TokenResponse getAccessTokenUsingKaKaoToken(SpringSecuritySocialOauthDTO.TokenRequest tokenRequest) throws IOException {

        KakaoAuth kaKaoAuth = new KakaoAuth(kaKaoUserInfoTemplate);

        SocialVendorOauthDTO.KaKaoUserInfo kaKaoUserInfo = kaKaoAuth.getKakaoUserInfo(tokenRequest.getAccessToken());
        if(kaKaoUserInfo.getKakaoAccount() == null){
            throw new SocialEmailNotProvidedException("소셜이 사용자의 이메일 확인 권한을 허용하지 않았습니다.");
        }
        Customer customer = customerRepository.findByKakaoIdName(kaKaoUserInfo.getKakaoAccount().getEmail()).orElse(null);

        return socialCustomTokenService.createAccessToken(customer, tokenRequest.getClientId());
    }

    public SpringSecuritySocialOauthDTO.CreateCustomerResponse createKakaoCustomer(SpringSecuritySocialOauthDTO.CreateCustomerRequest createCustomerRequest)
            throws IOException, DataIntegrityViolationException  {

        KakaoAuth kaKaoAuth = new KakaoAuth(kaKaoUserInfoTemplate);

        SocialVendorOauthDTO.KaKaoUserInfo kaKaoUserInfo = kaKaoAuth.getKakaoUserInfo(createCustomerRequest.getAccessToken());

        Customer customer = customerRepository.findByCi(createCustomerRequest.getCi()).orElse(null);
        if(customer == null){

            // 사용자 생성하고 포인트 주기 (Transaction)
            Customer justNowCreatedCustomer = customerRepositorySupport.createKakaoCustomerWithPoints(createCustomerRequest, kaKaoUserInfo);

            // 위에만 Transcation 분리하였으므로, 여기에서 실패하더라도 회원 가입을 불필요하게 다시 할 필요는 없게 된다.
            SpringSecuritySocialOauthDTO.TokenResponse tokenResponse = socialCustomTokenService.createAccessToken(justNowCreatedCustomer, appUserClientId);

            return new SpringSecuritySocialOauthDTO.CreateCustomerResponse(justNowCreatedCustomer, tokenResponse);
        }else{
            throw new AlreadySocialRegisteredException(SocialOauthMessageCreator.alreadySocialRegisteredException(customer));
        }

    }


    public SpringSecuritySocialOauthDTO.TokenResponse getAccessTokenUsingNaverToken(SpringSecuritySocialOauthDTO.TokenRequest tokenRequest) throws IOException {

        NaverAuth naverAuth = new NaverAuth(naverUserInfoTemplate);

        SocialVendorOauthDTO.NaverUserInfo naverUserInfo = naverAuth.getNaverUserInfo(tokenRequest.getAccessToken());
        if(naverUserInfo.getResponse() == null || naverUserInfo.getResponse().getEmail() == null){
            throw new SocialUnauthorizedException("소셜로 부터 올바른 응답을 받지 못했습니다. 문제가 지속된다면 관리자에게 문의하십시오.");
        }

        Customer customer = customerRepository.findByNaverIdName(naverUserInfo.getResponse().getEmail()).orElse(null);

        return socialCustomTokenService.createAccessToken(customer, tokenRequest.getClientId());
    }


    public SpringSecuritySocialOauthDTO.CreateCustomerResponse createNaverCustomer(SpringSecuritySocialOauthDTO.CreateCustomerRequest createCustomerRequest)
            throws IOException, DataIntegrityViolationException {

        NaverAuth naverAuth = new NaverAuth(naverUserInfoTemplate);

        SocialVendorOauthDTO.NaverUserInfo naverUserInfo = naverAuth.getNaverUserInfo(createCustomerRequest.getAccessToken());

        Customer customer = customerRepository.findByCi(createCustomerRequest.getCi()).orElse(null);
        if(customer == null){

            // 사용자 생성하고 포인트 주기 (Transaction)
            Customer justNowCreatedCustomer = customerRepositorySupport.createNaverCustomerWithPoints(createCustomerRequest, naverUserInfo);

            SpringSecuritySocialOauthDTO.TokenResponse tokenResponse = socialCustomTokenService.createAccessToken(justNowCreatedCustomer, appUserClientId);
            return new SpringSecuritySocialOauthDTO.CreateCustomerResponse(justNowCreatedCustomer, tokenResponse);

        }else{
            throw new AlreadySocialRegisteredException(SocialOauthMessageCreator.alreadySocialRegisteredException(customer));
        }

    }

    public SpringSecuritySocialOauthDTO.TokenResponse getAccessTokenUsingGoogleToken(SpringSecuritySocialOauthDTO.TokenRequest tokenRequest) throws IOException {

        GoogleAuth googleAuth = new GoogleAuth(googleUserInfoTemplate);

        SocialVendorOauthDTO.GoogleUserInfo googleUserInfo = googleAuth.getGoogleUserInfo(tokenRequest.getAccessToken());

        Customer customer = customerRepository.findByGoogleIdName(googleUserInfo.getSub()).orElse(null);

        return socialCustomTokenService.createAccessToken(customer, tokenRequest.getClientId());
    }


    public SpringSecuritySocialOauthDTO.CreateCustomerResponse createGoogleCustomer(SpringSecuritySocialOauthDTO.CreateCustomerRequest createCustomerRequest)
            throws IOException, DataIntegrityViolationException {

        GoogleAuth googleAuth = new GoogleAuth(googleUserInfoTemplate);

        SocialVendorOauthDTO.GoogleUserInfo googleUserInfo = googleAuth.getGoogleUserInfo(createCustomerRequest.getAccessToken());

        Customer customer = customerRepository.findByCi(createCustomerRequest.getCi()).orElse(null);
        if(customer == null){

            Customer justNowCreatedCustomer = customerRepositorySupport.createGoogleCustomerWithPoints(createCustomerRequest, googleUserInfo);

            SpringSecuritySocialOauthDTO.TokenResponse tokenResponse = socialCustomTokenService.createAccessToken(justNowCreatedCustomer, appUserClientId);
            return new SpringSecuritySocialOauthDTO.CreateCustomerResponse(justNowCreatedCustomer, tokenResponse);

        }else{
            throw new AlreadySocialRegisteredException(SocialOauthMessageCreator.alreadySocialRegisteredException(customer));
        }

    }


    public String redirectWithTokenResponseUsingAppleToken(SpringSecuritySocialOauthDTO.NonDependentTokenRequest
                                                        nonDependentTokenRequest, AppleUserInfo appleUserInfo, String hostName, String scheme, String idToken) throws IOException {

        Customer customer = customerRepository.findByAppleIdName(appleUserInfo.getSub()).orElse(null);

        return socialCustomTokenService.createAccessTokenToRedirect(customer, nonDependentTokenRequest.getClientId(), hostName, scheme, idToken);
    }

    public SpringSecuritySocialOauthDTO.CreateCustomerResponse createAppleCustomer(SpringSecuritySocialOauthDTO.CreateAppleCustomerRequest
                                                                                           createAppleCustomerRequest)
            throws DataIntegrityViolationException {

        Customer customer = customerRepository.findByCi(createAppleCustomerRequest.getCi()).orElse(null);
        if(customer == null){

            AppleUserInfo appleUserInfo = appleService.getAppleUserInfo(createAppleCustomerRequest.getIdToken());

            Customer justNowCreatedCustomer = customerRepositorySupport.createAppleCustomerWithPoints(createAppleCustomerRequest, appleUserInfo);

            SpringSecuritySocialOauthDTO.TokenResponse tokenResponse = socialCustomTokenService.createAccessToken(justNowCreatedCustomer, appUserClientId);
            return new SpringSecuritySocialOauthDTO.CreateCustomerResponse(justNowCreatedCustomer, tokenResponse);

        }else{
            throw new AlreadySocialRegisteredException(SocialOauthMessageCreator.alreadySocialRegisteredException(customer));
        }

    }


}
