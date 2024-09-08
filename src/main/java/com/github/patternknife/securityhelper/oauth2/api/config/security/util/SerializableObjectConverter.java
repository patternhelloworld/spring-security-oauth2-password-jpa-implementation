package com.github.patternknife.securityhelper.oauth2.api.config.security.util;


import org.apache.tomcat.util.codec.binary.Base64;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.util.SerializationUtils;

import java.util.Arrays;


public class SerializableObjectConverter {

    public static String serializeAuthentication(OAuth2Authorization object) {
        try {
            byte[] bytes = SerializationUtils.serialize(object);
            return Base64.encodeBase64String(bytes);
        } catch (Exception e) {
            e.printStackTrace();
            throw e;
        }
    }

    public static String serializeAccessToken(OAuth2AccessToken object) {
        try {
            byte[] bytes = SerializationUtils.serialize(object);
            return Base64.encodeBase64String(bytes);
        } catch (Exception e) {
            e.printStackTrace();
            throw e;
        }
    }

    public static String serializeRefreshToken(OAuth2RefreshToken object) {
        try {
            byte[] bytes = SerializationUtils.serialize(object);
            return Base64.encodeBase64String(bytes);
        } catch (Exception e) {
            e.printStackTrace();
            throw e;
        }
    }

    public static OAuth2Authorization deserializeToAuthentication(String encodedObject) {
        try {
            byte[] bytes = Base64.decodeBase64(encodedObject);
            return (OAuth2Authorization) SerializationUtils.deserialize(bytes);
        } catch (Exception e) {
            e.printStackTrace();
            throw e;
        }
    }

    public static OAuth2AccessToken deserializeToAccessToken(String encodedObject) {
        try {
            byte[] bytes = Base64.decodeBase64(Arrays.toString(encodedObject.getBytes()));
            return (OAuth2AccessToken) SerializationUtils.deserialize(bytes);
        } catch (Exception e) {
            e.printStackTrace();
            throw e;
        }
    }

    public static OAuth2RefreshToken deserializeToRefreshToken(String encodedObject) {
        try {
            byte[] bytes = Base64.decodeBase64(encodedObject);
            return (OAuth2RefreshToken) SerializationUtils.deserialize(bytes);
        } catch (Exception e) {
            e.printStackTrace();
            throw e;
        }
    }
}