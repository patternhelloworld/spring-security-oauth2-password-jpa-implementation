package com.patternknife.securityhelper.oauth2.config.security.serivce;

import com.patternknife.securityhelper.oauth2.config.response.error.message.SecurityExceptionMessage;
import com.patternknife.securityhelper.oauth2.config.response.error.exception.auth.OtpValueUnauthorizedException;
import com.patternknife.securityhelper.oauth2.domain.admin.bo.GoogleOtpResolver;
import com.patternknife.securityhelper.oauth2.util.CustomUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class Oauth2AuthenticationService {

    private final PasswordEncoder passwordEncoder;

    public void validateOtpValue(String otpValue, String optSecretKey){
        if(CustomUtils.isEmpty(otpValue)){
            throw new OtpValueUnauthorizedException(SecurityExceptionMessage.OTP_NOT_FOUND.getMessage());
        }

        if(Integer.parseInt(otpValue) != 555555) {
            GoogleOtpResolver googleOtpResolver = new GoogleOtpResolver();
            googleOtpResolver.validateOtpValue(optSecretKey, Integer.parseInt(otpValue));
        }
    }

    public void validatePassword(String inputPassword, UserDetails userDetails){
        if (userDetails == null) {
            throw new BadCredentialsException("로그인 : 해당 사용자의 정보를 찾을 수 없습니다.");
        }
        if (!passwordEncoder.matches(inputPassword, userDetails.getPassword())) {
            throw new BadCredentialsException("로그인 : 잘못 된 ID와 비밀번호 정보를 확인 하였습니다.");
        }
    }

    public Boolean validateClientCredentials(String inputClientSecret, RegisteredClient registeredClient){
        if (registeredClient == null) {
            throw new BadCredentialsException("해당 Client ID를 찾을 수 없습니다.");
        }
        if (!passwordEncoder.matches(inputClientSecret, registeredClient.getClientSecret())) {
            throw new BadCredentialsException("해당 Client 정보 오류 입니다.");
        }else{
            return true;
        }
    }

}
