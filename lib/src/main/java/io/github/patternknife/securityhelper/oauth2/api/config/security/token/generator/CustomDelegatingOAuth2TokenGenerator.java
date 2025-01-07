package io.github.patternknife.securityhelper.oauth2.api.config.security.token.generator;

import org.springframework.context.annotation.Configuration;
import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.util.Assert;

import java.util.Collections;
import java.util.List;

import static java.util.Arrays.asList;

@Configuration
public class CustomDelegatingOAuth2TokenGenerator implements OAuth2TokenGenerator<OAuth2Token> {

    private final List<OAuth2TokenGenerator<? extends OAuth2Token>> tokenGenerators;

    @SafeVarargs
    public CustomDelegatingOAuth2TokenGenerator(OAuth2TokenGenerator<? extends OAuth2Token>... tokenGenerators) {
        Assert.notEmpty(tokenGenerators, "tokenGenerators cannot be empty");
        Assert.noNullElements(tokenGenerators, "tokenGenerator cannot be null");
        this.tokenGenerators = Collections.unmodifiableList(asList(tokenGenerators));
    }

    @Nullable
    @Override
    public OAuth2Token generate(OAuth2TokenContext context) {
        for (OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator : this.tokenGenerators) {
            if (tokenGenerator instanceof CustomDelegatingOAuth2TokenGenerator) {
                boolean b = tokenGenerators.get(0) instanceof CustomDelegatingOAuth2TokenGenerator;
                if(b){
                    CustomDelegatingOAuth2TokenGenerator c = (CustomDelegatingOAuth2TokenGenerator) tokenGenerators.get(0);
                    boolean d = c.tokenGenerators.get(0) instanceof JwtGenerator;
                    boolean e = c.tokenGenerators.get(1) instanceof OAuth2RefreshTokenGenerator;
                    if(d && context.getTokenType().equals(OAuth2TokenType.ACCESS_TOKEN)){
                      return  ((OAuth2AccessTokenGenerator) c.tokenGenerators.get(0)).generate(context);
                    }
                    if (e && context.getTokenType().equals(OAuth2TokenType.REFRESH_TOKEN)){
                       return  ((OAuth2RefreshTokenGenerator) c.tokenGenerators.get(1)).generate(context);
                    }
                }
            }

        }
        return null;
    }

    public void setCustomizer(GeneratorType type, OAuth2TokenCustomizer<JwtEncodingContext> customizer) {
        switch (type) {
            case ACCESS_TOKEN:
                for (OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator : this.tokenGenerators) {
                    if (tokenGenerator instanceof CustomDelegatingOAuth2TokenGenerator) {
                        boolean b = tokenGenerators.get(0) instanceof CustomDelegatingOAuth2TokenGenerator;
                        if(b){
                            CustomDelegatingOAuth2TokenGenerator c = (CustomDelegatingOAuth2TokenGenerator) tokenGenerators.get(0);
                           boolean d = c.tokenGenerators.get(0) instanceof JwtGenerator;
                            if(d){
                                ((JwtGenerator) c.tokenGenerators.get(0)).setJwtCustomizer(customizer);
                            }
                        }
                    }
                }
                break;
            default:
                // Handle other types if necessary
                break;
        }
    }

    public enum GeneratorType {
        ACCESS_TOKEN,
        REFRESH_TOKEN
    }
}
