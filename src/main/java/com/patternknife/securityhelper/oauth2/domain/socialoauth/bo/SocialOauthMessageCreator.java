package com.patternknife.securityhelper.oauth2.domain.socialoauth.bo;

import com.patternknife.securityhelper.oauth2.domain.customer.entity.Customer;

public class SocialOauthMessageCreator {

    public static String alreadySocialRegisteredException(Customer customer){

        String re = customer.getName() + " 님은 ";

        if(customer.getKakaoIdName() != null){
            re += "KAKAO (ID : " + customer.getKakaoIdName() + ")";
        } else if(customer.getNaverIdName() != null){
            re += "NAVER (ID : " + customer.getNaverIdName() + ")";
        } else if(customer.getGoogleIdName() != null){
            re += "GOOGLE (ID : " + customer.getGoogleIdName() + ")";
        } else if(customer.getAppleIdName() != null){
            re += "APPLE (ID : " + customer.getAppleIdName() + ")";
        } else{
            re += "일반 (ID : " + customer.getIdName() + ")";
        }

        re += " 계정으로 소셜 로그인 가입 하였습니다.";

        return re;

    }
}
