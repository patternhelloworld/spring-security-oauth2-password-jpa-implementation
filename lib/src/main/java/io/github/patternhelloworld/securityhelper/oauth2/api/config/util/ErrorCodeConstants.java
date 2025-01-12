package io.github.patternhelloworld.securityhelper.oauth2.api.config.util;


/*
*   Consider the following method in "spring-authorization-server"
*
*       static String normalizeUserCode(String userCode) {
            Assert.hasText(userCode, "userCode cannot be empty");
            StringBuilder sb = new StringBuilder(userCode.toUpperCase().replaceAll("[^A-Z\\d]+", ""));
            Assert.isTrue(sb.length() == 8, "userCode must be exactly 8 alpha/numeric characters");
            sb.insert(4, '-');
            return sb.toString();
	}
* */
public class ErrorCodeConstants {
    public static final String REDIRECT_TO_LOGIN = "REDIRECTTOLOGIN";
    public static final String REDIRECT_TO_CONSENT = "REDIRECTTOCONSENT";
}
