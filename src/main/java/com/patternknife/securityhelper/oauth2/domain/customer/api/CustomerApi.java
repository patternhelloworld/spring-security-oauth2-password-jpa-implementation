package com.patternknife.securityhelper.oauth2.domain.customer.api;


import com.patternknife.securityhelper.oauth2.config.response.GlobalSuccessPayload;
import com.patternknife.securityhelper.oauth2.config.response.error.exception.data.ResourceNotFoundException;
import com.patternknife.securityhelper.oauth2.config.security.annotation.UserCustomerOnly;
import com.patternknife.securityhelper.oauth2.config.security.principal.AccessTokenUserInfo;
import com.patternknife.securityhelper.oauth2.domain.customer.dao.CustomerRepository;
import com.patternknife.securityhelper.oauth2.domain.customer.dto.CustomerReqDTO;
import com.patternknife.securityhelper.oauth2.domain.customer.dto.CustomerResDTO;
import com.patternknife.securityhelper.oauth2.domain.customer.service.CustomerService;
import com.patternknife.securityhelper.oauth2.util.CustomUtils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/v1")
@AllArgsConstructor
public class CustomerApi {

    private final CustomerService customerService;
    private final OAuth2AuthorizationService oAuth2AuthorizationService;
    private final CustomerRepository customerRepository;

    @UserCustomerOnly
    @PreAuthorize("isAuthenticated()")
    @GetMapping("/customers/me")
    public GlobalSuccessPayload<CustomerResDTO.IdNameWithAccessTokenRemainingSeconds> getCustomerSelf(@AuthenticationPrincipal AccessTokenUserInfo accessTokenUserInfo,
                                                                                                      @RequestHeader("Authorization") String authorizationHeader) throws ResourceNotFoundException {


        String token = authorizationHeader.substring("Bearer ".length());

        int accessTokenRemainingSeconds = 0;

        OAuth2Authorization oAuth2Authorization = oAuth2AuthorizationService.findByToken(token, OAuth2TokenType.ACCESS_TOKEN);

        if(oAuth2Authorization != null) {
            OAuth2AccessToken oAuth2AccessToken = oAuth2Authorization.getAccessToken().getToken();

            if (oAuth2AccessToken != null) {
                Instant now = Instant.now();
                Instant expiresAt = oAuth2AccessToken.getExpiresAt();
                accessTokenRemainingSeconds = Math.toIntExact(Duration.between(now, expiresAt).getSeconds());

            }
        }

        return new GlobalSuccessPayload<>(new CustomerResDTO.IdNameWithAccessTokenRemainingSeconds(customerRepository.findByIdName(accessTokenUserInfo.getUsername())
                .orElseThrow(() -> new ResourceNotFoundException("Couldn't find the user (username : " + accessTokenUserInfo.getUsername() + ")")), accessTokenRemainingSeconds));

    }


    @UserCustomerOnly
    @PreAuthorize("isAuthenticated()")
    @PatchMapping("/customers/me/delete")
    public GlobalSuccessPayload<CustomerResDTO.Id> deleteMe(@AuthenticationPrincipal AccessTokenUserInfo accessTokenUserInfo) {

        customerService.deleteCustomer(accessTokenUserInfo);

        return new GlobalSuccessPayload<>(new CustomerResDTO.Id(accessTokenUserInfo.getAdditionalAccessTokenUserInfo().getId()));
    }

    @UserCustomerOnly
    @GetMapping("/customers/me/logout")
    public GlobalSuccessPayload<Map<String, Boolean>> logoutCustomer(HttpServletRequest request) {

        DefaultBearerTokenResolver resolver = new DefaultBearerTokenResolver();
        String token = resolver.resolve(request);

        Map<String, Boolean> response = new HashMap<>();

        response.put("logout", Boolean.TRUE);

        try {
            OAuth2Authorization oAuth2Authorization = oAuth2AuthorizationService.findByToken(token, OAuth2TokenType.ACCESS_TOKEN);

            if(oAuth2Authorization != null) {
                oAuth2AuthorizationService.remove(oAuth2Authorization);
            }

        } catch (Exception e) {
            response.put("logout", Boolean.FALSE);
            CustomUtils.createNonStoppableErrorMessage("Errors in process of logging out", e);
        }


        return new GlobalSuccessPayload<>(response);
    }



    @PreAuthorize("@resourceServerAuthorityChecker.hasRole('CUSTOMER_ADMIN')")
    @PutMapping("/customers/{id}")
    public GlobalSuccessPayload<CustomerResDTO.Id> update(@PathVariable final long id, @Valid @RequestBody final CustomerReqDTO.Update dto)
            throws ResourceNotFoundException {
        return new GlobalSuccessPayload<>(customerService.update(id, dto));
    }

    @PreAuthorize("@resourceServerAuthorityChecker.hasRole('CUSTOMER_ADMIN')")
    @PatchMapping("/customers/{id}/delete")
    public GlobalSuccessPayload<CustomerResDTO.IdAdminId> deleteCustomer(@PathVariable final long id, @AuthenticationPrincipal AccessTokenUserInfo accessTokenUserInfo) {

        customerService.deleteCustomer(id, accessTokenUserInfo.getAdditionalAccessTokenUserInfo().getId());

        return new GlobalSuccessPayload<>(new CustomerResDTO.IdAdminId(id, accessTokenUserInfo.getAdditionalAccessTokenUserInfo().getId()));
    }

    @PreAuthorize("@resourceServerAuthorityChecker.hasRole('CUSTOMER_ADMIN')")
    @PatchMapping("/customers/{id}/restore")
    public GlobalSuccessPayload<CustomerResDTO.IdAdminId> restoreCustomer(@PathVariable final long id, @AuthenticationPrincipal AccessTokenUserInfo accessTokenUserInfo) {

        customerService.restoreCustomer(id);

        return new GlobalSuccessPayload<>(new CustomerResDTO.IdAdminId(id, accessTokenUserInfo.getAdditionalAccessTokenUserInfo().getId()));
    }


}
