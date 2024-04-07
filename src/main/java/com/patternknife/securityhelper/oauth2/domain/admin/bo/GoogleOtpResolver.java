package com.patternknife.securityhelper.oauth2.domain.admin.bo;

import com.patternknife.securityhelper.oauth2.config.response.error.exception.auth.OtpValueUnauthorizedException;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import com.warrenstrange.googleauth.GoogleAuthenticatorQRGenerator;

import static org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationServerMetadataClaimNames.ISSUER;


public class GoogleOtpResolver {

    public GoogleAuthenticatorKey generateOtpSecretKey(){
        GoogleAuthenticator googleAuthenticator = new GoogleAuthenticator();
        return googleAuthenticator.createCredentials();
    }

    public String generateOtpSecretQrCodeUrl(String oauth2UserName, GoogleAuthenticatorKey secretKey){
        return GoogleAuthenticatorQRGenerator.getOtpAuthTotpURL(ISSUER, oauth2UserName, secretKey);
    }

    public void validateOtpValue(String secretKey, int otpValue) throws OtpValueUnauthorizedException {
        GoogleAuthenticator googleAuthenticator = new GoogleAuthenticator();
        int serverOtpValue = googleAuthenticator.getTotpPassword(secretKey);
        if(serverOtpValue != otpValue) {
            throw new OtpValueUnauthorizedException("현재 OTP 값이 만료되어 (" + otpValue + ") 이 서버 OTP 값 (" + serverOtpValue + ") 과 일치하지 않습니다. 재입력 하십시오.");
        }
    }
}
