package com.github.patternknife.securityhelper.oauth2.api.config.security.token.generator;

import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedHashMap;
import java.util.Map;

public class CustomAuthenticationKeyGenerator {

    /*
    *   KEY : username + client_id + app_token
    * */
    public static String hashUniqueCompositeColumnsToAuthenticationId(OAuth2Authorization authorization, String appToken) {
        Map<String, String> values = new LinkedHashMap();

        if (authorization.getRegisteredClientId() != null) {
            values.put("username", authorization.getPrincipalName());
        }

        values.put("client_id", authorization.getRegisteredClientId());
/*        if (authorizationRequest.getScope() != null) {
            values.put("scope", OAuth2Utils.formatParameterList(new TreeSet(authorizationRequest.getScope())));
        }*/
        values.put("app_token", appToken);

        return generateKey(values);
    }

    protected static String generateKey(Map<String, String> values) {
        try {
            MessageDigest digest = MessageDigest.getInstance("MD5");
            byte[] bytes = digest.digest(values.toString().getBytes("UTF-8"));
            return String.format("%032x", new BigInteger(1, bytes));
        } catch (NoSuchAlgorithmException var4) {
            throw new IllegalStateException("MD5 algorithm not available.  Fatal (should be in the JDK).", var4);
        } catch (UnsupportedEncodingException var5) {
            throw new IllegalStateException("UTF-8 encoding not available.  Fatal (should be in the JDK).", var5);
        }
    }

    public static String hashTokenValueToTokenId(String value) {
        if(value == null) {
            return null;
        } else {
            MessageDigest digest;
            try {
                digest = MessageDigest.getInstance("MD5");
            } catch (NoSuchAlgorithmException var5) {
                throw new IllegalStateException("MD5 algorithm not available.  Fatal (should be in the JDK).");
            }

            try {
                byte[] e = digest.digest(value.getBytes("UTF-8"));
                return String.format("%032x", new Object[]{new BigInteger(1, e)});
            } catch (UnsupportedEncodingException var4) {
                throw new IllegalStateException("UTF-8 encoding not available.  Fatal (should be in the JDK).");
            }
        }
    }
}
