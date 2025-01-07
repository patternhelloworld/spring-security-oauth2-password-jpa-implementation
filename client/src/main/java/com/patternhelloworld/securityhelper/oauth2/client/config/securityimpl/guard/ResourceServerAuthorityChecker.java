package com.patternhelloworld.securityhelper.oauth2.client.config.securityimpl.guard;

import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.serivce.persistence.authorization.OAuth2AuthorizationServiceImpl;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.serivce.userdetail.ConditionalDetailsService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.stereotype.Service;

@RequiredArgsConstructor
@Service
public class ResourceServerAuthorityChecker {

    private final OAuth2AuthorizationServiceImpl authorizationService;
    private final ConditionalDetailsService conditionalDetailsService;
    private final RegisteredClientRepository registeredClientRepository;


    public boolean hasAnyAdminRole() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (!(authentication instanceof BearerTokenAuthentication bearerTokenAuth)) {
            return false;
        }

        String bearerAccessToken = bearerTokenAuth.getToken().getTokenValue();

        OAuth2Authorization oAuth2Authorization = authorizationService.findByToken(bearerAccessToken, OAuth2TokenType.ACCESS_TOKEN);
        if (oAuth2Authorization == null) {
            return false;
        }

        UserDetails userDetails = conditionalDetailsService.loadUserByUsername(
                oAuth2Authorization.getPrincipalName(),
                oAuth2Authorization.getAttribute("client_id")
        );

        // Check for any _ADMIN roles
        return userDetails.getAuthorities().stream()
                .anyMatch(authority -> authority.getAuthority().endsWith("_ADMIN"));
    }

    private boolean hasRoleOrSuperAdmin(String role) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null) {
            return false;
        }

        String bearerAccessToken = ((BearerTokenAuthentication) authentication).getToken().getTokenValue();

        OAuth2Authorization oAuth2Authorization = authorizationService.findByToken(bearerAccessToken, OAuth2TokenType.ACCESS_TOKEN);

        UserDetails userDetails = conditionalDetailsService.loadUserByUsername(oAuth2Authorization.getPrincipalName(), oAuth2Authorization.getAttribute("client_id"));

        // Check for SUPER_ADMIN role or the specific role
        return userDetails.getAuthorities().stream()
                .anyMatch(authority -> role.equals(authority.getAuthority())
                        || authority.getAuthority().equals(role));
    }

    public boolean hasAnyOfRoles(String[] roles) {
        for (String role : roles) {
            if (hasRoleOrSuperAdmin(role)) {
                return true;
            }
        }
        return false;
    }
    public boolean hasRole(String role) {
        return hasRoleOrSuperAdmin(role);
    }

}