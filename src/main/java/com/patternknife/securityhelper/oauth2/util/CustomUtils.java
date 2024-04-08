package com.patternknife.securityhelper.oauth2.util;

import com.patternknife.securityhelper.oauth2.config.logger.module.ResponseSuccessLogConfig;
import com.patternknife.securityhelper.oauth2.config.security.enums.MobileOSType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.SecureRandom;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

public class CustomUtils {

    private static final Logger logger = LoggerFactory.getLogger(ResponseSuccessLogConfig.class);


    public static boolean isEmpty(Object obj) {
        if (obj == null) { return true; }
        if ((obj instanceof String) && (((String)obj).trim().length() == 0)) { return true; }
        if (obj instanceof Map) { return ((Map<?, ?>)obj).isEmpty(); }
        if (obj instanceof List) { return ((List<?>)obj).isEmpty(); }
        if (obj instanceof Object[]) { return (((Object[])obj).length == 0); }

        return false;
    }

    public static String createUUID(){
        return UUID.randomUUID().toString().replace("-", "");
    }

    public static String createSequentialUUIDStringReplaceHyphen(){
        return CustomUtils.createSequentialUUIDString().replace("-", "");
    }

    public static String createSequentialUUIDString(){
        byte[] randomBytes = new byte[10];
        SecureRandom secureRandom = new SecureRandom();

        secureRandom.nextBytes(randomBytes);

        long timestamp = Instant.now().getEpochSecond() / 10000L;

        byte[] timestampBytes = BitConverter.getBytes(timestamp);

        if(BitConverter.IsLittleEndian())
            Collections.reverse(Arrays.asList(timestampBytes));

        byte[] guidBytes = new byte[16];

        System.arraycopy(timestampBytes, 2, guidBytes, 0, 6);
        System.arraycopy(randomBytes, 0, guidBytes, 6, 10);

        if (BitConverter.IsLittleEndian()) {
            // 0-3 reverse
            reverse(guidBytes, 0, 4);
            // 4-5 reverse
            reverse(guidBytes, 4, 2);
        }

        return UUID.nameUUIDFromBytes(guidBytes).toString();
    }

    public static void reverse(byte[] contents, int index, int length){
        byte temp;
        for(int idx = index; idx < index + length; idx++){
            temp = contents[idx];
            contents[idx] = contents[contents.length - idx - 1];
            contents[contents.length - idx - 1] = temp;
        }
    }


    public static <T> Optional<T> getAsOptional(List<T> list, int index) {
        try {
            return Optional.of(list.get(index));
        } catch (ArrayIndexOutOfBoundsException e) {
            return Optional.empty();
        }
    }

    public static void createNonStoppableErrorMessage(String message, Throwable ex){
        try {
            logger.error("[NON-STOPPABLE ERROR] : " + message + " / " + ex.getMessage() + " / " + ex.getStackTrace()[0] + " / Thread ID = " + Thread.currentThread().getId());
        }catch (Exception e){
            e.printStackTrace();
        }
    }

    public static void createNonStoppableErrorMessage(String message, String ex){
        try {
            logger.error("[NON-STOPPABLE ERROR] : " + message + " / " + ex + " / " + " / Thread ID = " + Thread.currentThread().getId());
        }catch (Exception e){
            e.printStackTrace();
        }
    }



    public static LocalDateTime convertDateStrToLocalDateTime(String t, int h, int m, int s){
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd");
        LocalDate date = LocalDate.parse(t, formatter);
        LocalDateTime dateTime = date.atTime(h, m, s);

        return dateTime;
    }

    public static LocalDateTime convertDateStrToLocalDateTime(String t){
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
        LocalDateTime dateTime = LocalDateTime.parse(t, formatter);
        return dateTime;
    }

    public static LocalDate convertDateStrToLocalDate(String t){
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd");
        LocalDate date = LocalDate.parse(t, formatter);

        return date;
    }

    public static String removeSpecialCharacters(String phoneNumber) {
        return phoneNumber.replaceAll("[^0-9]", "");
    }

    public static String maskIdName(String idName) {
        if (idName == null || idName.length() == 0) {
            return "";
        }

        int unmaskedLength = (int) (idName.length() * 0.3);
        String unmaskedPart = idName.substring(0, unmaskedLength);

        StringBuilder result = new StringBuilder();
        for (int i = 0; i < idName.length() - unmaskedLength; i++) {
            result.append("*");
        }
        String maskedPart = result.toString();
        return unmaskedPart + maskedPart;
    }

    public static Integer[] commaSplitStrToIntegerArr(String input){

        String[] parts = input.split(",");

        Integer[] integers = new Integer[parts.length];

        for (int i = 0; i < parts.length; i++) {
            integers[i] = Integer.parseInt(parts[i].trim());
        }

        return integers;
    }

    public static MobileOSType getMobileOperatingSystem(String userAgent) {
        if (userAgent != null && userAgent.matches(".*Windows Phone.*")) {
            return MobileOSType.WINDOWS_PHONE;
        }
        if (userAgent != null && userAgent.matches(".*Android.*")) {
            return MobileOSType.ANDROID;
        }
        if (userAgent != null && (userAgent.matches(".*iPad.*") || userAgent.matches(".*iPhone.*") || userAgent.matches(".*iPod.*") || userAgent.matches(".*CFNetwork.*") || userAgent.matches(".*Darwin.*"))) {
            return MobileOSType.IOS;
        }
        return MobileOSType.UNKNOWN;
    }

}
