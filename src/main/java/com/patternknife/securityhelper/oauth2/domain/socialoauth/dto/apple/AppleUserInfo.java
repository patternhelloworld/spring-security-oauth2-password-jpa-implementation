package com.patternknife.securityhelper.oauth2.domain.socialoauth.dto.apple;

public class AppleUserInfo {

    private String iss;
    private String aud;
    private Long exp;
    private Long iat;
    private String sub;
    private String nonce;
    private String c_hash;
    private String at_hash;
    private String email;
    private String email_verified;
    private String is_private_email;
    private Long auth_time;
    private boolean nonce_supported;

    public String getIss() {
        return iss;
    }

    public void setIss(String iss) {
        this.iss = iss;
    }

    public String getAud() {
        return aud;
    }

    public void setAud(String aud) {
        this.aud = aud;
    }

    public Long getExp() {
        return exp;
    }

    public void setExp(Long exp) {
        this.exp = exp;
    }

    public Long getIat() {
        return iat;
    }

    public void setIat(Long iat) {
        this.iat = iat;
    }

    public String getSub() {
        return sub;
    }

    public void setSub(String sub) {
        this.sub = sub;
    }

    public String getNonce() {
        return nonce;
    }

    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    public String getC_hash() {
        return c_hash;
    }

    public void setC_hash(String c_hash) {
        this.c_hash = c_hash;
    }

    public String getAt_hash() {
        return at_hash;
    }

    public void setAt_hash(String at_hash) {
        this.at_hash = at_hash;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getEmail_verified() {
        return email_verified;
    }

    public void setEmail_verified(String email_verified) {
        this.email_verified = email_verified;
    }

    public String getIs_private_email() {
        return is_private_email;
    }

    public void setIs_private_email(String is_private_email) {
        this.is_private_email = is_private_email;
    }

    public Long getAuth_time() {
        return auth_time;
    }

    public void setAuth_time(Long auth_time) {
        this.auth_time = auth_time;
    }

    public boolean isNonce_supported() {
        return nonce_supported;
    }

    public void setNonce_supported(boolean nonce_supported) {
        this.nonce_supported = nonce_supported;
    }

    @Override
    public String toString() {
        return "{" +
                "iss='" + iss + '\'' +
                ", aud='" + aud + '\'' +
                ", exp=" + exp +
                ", iat=" + iat +
                ", sub='" + sub + '\'' +
                ", nonce='" + nonce + '\'' +
                ", c_hash='" + c_hash + '\'' +
                ", at_hash='" + at_hash + '\'' +
                ", email='" + email + '\'' +
                ", email_verified='" + email_verified + '\'' +
                ", is_private_email='" + is_private_email + '\'' +
                ", auth_time=" + auth_time +
                ", nonce_supported=" + nonce_supported +
                '}';
    }
}
