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
public class EasyPlusErrorCodeConstants {
    public static final String REDIRECT_TO_LOGIN = "REDIRECTTOLOGIN";
    public static final String REDIRECT_TO_CONSENT = "REDIRECTTOCONSENT";
    public static final String MISSING_CLIENT_ID = "MISSINGCLIENTID";
    public static final String MISSING_REDIRECT_URI = "MISSINGREDIRECTURI";
    public static final String MISSING_STATE = "MISSINGSTATE";
    public static final String MISSING_RESPONSE_TYPE = "MISSINGRESPONSETYPE";
    public static final String WRONG_RESPONSE_TYPE = "WRONGRESPONSETYPE";
    public static final String SCOPE_MISMATCH = "SCOPEMISMATCH";

    public static final String MISSING_AUTHORIZATION_CODE = "MISSINGAUTHORIZATIONCODE";
    public static final String MISSING_USERNAME = "MISSINGUSERNAME";
    public static final String MISSING_PASSWORD = "MISSINGPASSWORD";
    public static final String MISSING_REFRESH_TOKEN = "MISSINGREFRESHTOKEN";

}
