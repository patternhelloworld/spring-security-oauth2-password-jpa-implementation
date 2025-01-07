package io.github.patternknife.securityhelper.oauth2.api.config.security.token.generator;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsSet;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import java.util.HashMap;
import java.util.Map;

public class CustomAccessTokenCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

    private final UserDetails userDetails;

    public CustomAccessTokenCustomizer(UserDetails userDetails) {
        this.userDetails = userDetails;
    }



/*    @Override
    public void customize(OAuth2TokenClaimsContext context) {
        if (context != null) {
            OAuth2TokenClaimsSet.Builder claimsSetBuilder = context.getClaims();

            // Serialize or transform the customer object to a suitable format for claims, if necessary
            // This example assumes customer information is transformed to a Map or a String.
            // The actual transformation depends on how you want to represent the customer information in the token.
            Map<String, Object> customerInfo = serializeCustomerToMap(this.userDetails); // Implement this method based on your needs

            // Add the custom user information claim
            claimsSetBuilder.claim("x_custom_userinfo", customerInfo);

        }


    }*/
    private Map<String, Object> serializeCustomerToMap(UserDetails userDetails) {
        // Implement the logic to transform the Customer object into a Map or another format suitable for JWT claims
        Map<String, Object> customerInfo = new HashMap<>();
        // Example transformation
        customerInfo.put("name", userDetails.getUsername());
        // Add other customer attributes as needed
        return customerInfo;
    }

    @Override
    public void customize(JwtEncodingContext context) {

    }
}
