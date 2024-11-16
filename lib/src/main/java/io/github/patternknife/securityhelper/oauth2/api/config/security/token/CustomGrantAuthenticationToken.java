package io.github.patternknife.securityhelper.oauth2.api.config.security.token;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;

public class CustomGrantAuthenticationToken extends AbstractAuthenticationToken {

    private final Object principal;
    private final AuthorizationGrantType grantType;
    private final Map<String, Object> additionalParameters;

    // Constructor
    public CustomGrantAuthenticationToken(AuthorizationGrantType grantType, Object principal, Map<String, Object> additionalParameters) {
        super(Collections.emptyList());
        this.grantType = grantType;
        this.principal = principal;
        this.additionalParameters = additionalParameters;
        setAuthenticated(false); // This should always be false initially
    }

    @Override
    public Collection<GrantedAuthority> getAuthorities() {
        if(principal instanceof UserDetails){
            return (Collection<GrantedAuthority>) ((UserDetails) principal).getAuthorities();
        }else{
            Object authoritiesObj = this.getAdditionalParameters().get("authorities");
            if (authoritiesObj instanceof Collection<?>) {
                Collection<?> rawCollection = (Collection<?>) authoritiesObj;
                for (Object obj : rawCollection) {
                    if (!(obj instanceof GrantedAuthority)) {
                        //        throw new ClassCastException("Element is not a GrantedAuthority");
                        return Collections.emptyList();
                    }
                }
                return (Collection<GrantedAuthority>) rawCollection;
            } else {
                return Collections.emptyList();
            }
        }




    }

    @Override
    public Object getCredentials() {
        return null; // Typically, credentials are not needed/used after authentication
    }

    @Override
    public Object getDetails() {
        return this.additionalParameters; // Details about the authentication request
    }

    @Override
    public Object getPrincipal() {
        return this.principal; // The authenticated user or client
    }

    @Override
    public boolean isAuthenticated() {
        return super.isAuthenticated(); // The authentication state
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        super.setAuthenticated(isAuthenticated); // Set the authentication state
    }

    public AuthorizationGrantType getGrantType() {
        return grantType;
    }

    public Map<String, Object> getAdditionalParameters() {
        return additionalParameters;
    }
}
