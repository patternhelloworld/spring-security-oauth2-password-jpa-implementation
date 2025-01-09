package io.github.patternhelloworld.securityhelper.oauth2.api.config.security.server;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import javax.crypto.spec.SecretKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;

@Configuration
public class EasyPlusJwtConfig {

    private static final Logger logger = LoggerFactory.getLogger(EasyPlusJwtConfig.class);

    @Value("${patternhelloworld.securityhelper.jwt.secret:5pAq6zRyX8bC3dV2wS7gN1mK9jF0hL4tUoP6iBvE3nG8xZaQrY7cW2fA}")
    private String jwtSecret;

    @Value("${patternhelloworld.securityhelper.jwt.algorithm:HmacSHA256}")
    private String algorithm;

    @Bean
    public JwtDecoder jwtDecoder() {
        byte[] keyBytes = Base64.getDecoder().decode(jwtSecret);
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, algorithm);
        return NimbusJwtDecoder.withSecretKey(secretKeySpec).build();
    }

    @Bean
    public JwtEncoder jwtEncoder() {
        return parameters -> {
            byte[] secretKeyBytes = Base64.getDecoder().decode(jwtSecret);
            SecretKeySpec secretKeySpec = new SecretKeySpec(secretKeyBytes, algorithm);

            try {
                MACSigner signer = new MACSigner(secretKeySpec);

                JWTClaimsSet.Builder claimsSetBuilder = new JWTClaimsSet.Builder();
                parameters.getClaims().getClaims().forEach((key, value) ->
                        claimsSetBuilder.claim(key, value instanceof Instant ? Date.from((Instant) value) : value)
                );
                JWTClaimsSet claimsSet = claimsSetBuilder.build();

                JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);

                SignedJWT signedJWT = new SignedJWT(header, claimsSet);
                signedJWT.sign(signer);

                return Jwt.withTokenValue(signedJWT.serialize())
                        .header("alg", header.getAlgorithm().getName())
                        .subject(claimsSet.getSubject())
                        .issuer(claimsSet.getIssuer())
                        .claims(claims -> claims.putAll(claimsSet.getClaims()))
                        .issuedAt(claimsSet.getIssueTime().toInstant())
                        .expiresAt(claimsSet.getExpirationTime().toInstant())
                        .build();
            } catch (Exception e) {
                throw new IllegalStateException("Error while signing the JWT", e);
            }
        };
    }
}
