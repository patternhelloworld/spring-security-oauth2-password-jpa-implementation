package com.patternknife.securityhelper.oauth2.domain.customer.api;


import com.patternknife.securityhelper.oauth2.config.response.GlobalSuccessPayload;
import com.patternknife.securityhelper.oauth2.config.response.error.exception.data.ResourceNotFoundException;
import com.patternknife.securityhelper.oauth2.config.security.annotation.UserCustomerOnly;
import com.patternknife.securityhelper.oauth2.config.security.serivce.OAuth2AuthorizationServiceImpl;
import com.patternknife.securityhelper.oauth2.config.security.principal.AccessTokenUserInfo;
import com.patternknife.securityhelper.oauth2.domain.customer.dao.CustomerRepository;
import com.patternknife.securityhelper.oauth2.domain.customer.dto.CustomerReqDTO;
import com.patternknife.securityhelper.oauth2.domain.customer.dto.CustomerResDTO;
import com.patternknife.securityhelper.oauth2.domain.customer.service.CustomerService;

import com.patternknife.securityhelper.oauth2.util.CommonConstant;
import com.patternknife.securityhelper.oauth2.util.CustomUtils;
import com.fasterxml.jackson.core.JsonProcessingException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.Page;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@RestController
@RequestMapping("/api/v1")
@AllArgsConstructor
public class CustomerApi {

    private final CustomerService customerService;
    private final OAuth2AuthorizationServiceImpl oAuth2AuthorizationServiceImpl;
    private final CustomerRepository customerRepository;

    @PreAuthorize("isAuthenticated()")
    @GetMapping("/customers/me")
    public GlobalSuccessPayload<CustomerResDTO.IdNameWithAccessTokenRemainingSeconds> getCustomerSelf(@AuthenticationPrincipal AccessTokenUserInfo accessTokenUserInfo,
                                                                                                      OAuth2Authorization oAuth2Authorization) throws ResourceNotFoundException {

        Integer accessTokenRemainingSeconds = null;

        OAuth2AccessToken oAuth2AccessToken = oAuth2Authorization.getAccessToken().getToken();

        if (oAuth2AccessToken != null) {
            Instant now = Instant.now();
            Instant expiresAt = oAuth2AccessToken.getExpiresAt();
            accessTokenRemainingSeconds = Math.toIntExact(Duration.between(now, expiresAt).getSeconds());

        }

        return new GlobalSuccessPayload<>(new CustomerResDTO.IdNameWithAccessTokenRemainingSeconds(customerRepository.findByIdName(accessTokenUserInfo.getUsername())
                .orElseThrow(() -> new ResourceNotFoundException("해당 사용자를 찾을 수 없습니다. (username : " + accessTokenUserInfo.getUsername() + ")")), accessTokenRemainingSeconds));

    }

    @PostMapping("/customers/create")
    public GlobalSuccessPayload<CustomerResDTO.IdWithTokenResponse> create(@Valid @RequestBody final CustomerReqDTO.Create dto)
            throws DataIntegrityViolationException {
        return new GlobalSuccessPayload<>(customerService.create(dto));
    }

    @GetMapping("/customers/find")
    public GlobalSuccessPayload<List<CustomerResDTO.IdNamesCreatedAt>> getIdNameByNameWithHp(@RequestParam(value = "name") String name, @RequestParam(value = "hp") String hp) {
        return new GlobalSuccessPayload<>(customerService.findIdNameByNameWithHp(name,hp));
    }

    @GetMapping("/customers/{idName}/id-exists")
    public GlobalSuccessPayload<Map<String,Boolean>> checkIdNameDuplicate(@PathVariable String idName) {
        Map<String,Boolean> resultMap = new HashMap<>();
        resultMap.put("exists", customerService.checkIdNameDuplicate(idName));
        return new GlobalSuccessPayload<>(resultMap);
    }

    @GetMapping("/customers/{hp}/hp-exists")
    public GlobalSuccessPayload<Map<String,Boolean>> checkHpDuplicate(@PathVariable String hp) {
        Map<String,Boolean> resultMap = new HashMap<>();
        resultMap.put("exists", customerService.checkHpDuplicate(hp));
        return new GlobalSuccessPayload<>(resultMap);
    }

    @PreAuthorize("isAuthenticated()")
    @PatchMapping("/customers/me/delete")
    public GlobalSuccessPayload<CustomerResDTO.Id> deleteMe(@AuthenticationPrincipal AccessTokenUserInfo accessTokenUserInfo) {

        customerService.deleteCustomer(accessTokenUserInfo);

        return new GlobalSuccessPayload<>(new CustomerResDTO.Id(accessTokenUserInfo.getAdditionalAccessTokenUserInfo().getId()));
    }


    @PreAuthorize("isAuthenticated()")
    @UserCustomerOnly
    @GetMapping("/customers/me/resources")
    public GlobalSuccessPayload<CustomerResDTO.OneWithResources> getCustomerMeWithResources(@AuthenticationPrincipal AccessTokenUserInfo accessTokenUserInfo) throws ResourceNotFoundException, JsonProcessingException {
        return new GlobalSuccessPayload<>(customerService.findCustomerOneWithResources(accessTokenUserInfo.getAdditionalAccessTokenUserInfo().getId()));
    }


    @GetMapping("/customers/me/logout")
    public GlobalSuccessPayload<Map<String, Boolean>> logoutCustomer(HttpServletRequest request,
                                                                     @AuthenticationPrincipal AccessTokenUserInfo accessTokenUserInfo) {
        DefaultBearerTokenResolver resolver = new DefaultBearerTokenResolver();
        String token = resolver.resolve(request);

        Map<String, Boolean> response = new HashMap<>();

        response.put("logout", Boolean.TRUE);

        try {
            OAuth2Authorization oAuth2Authorization = oAuth2AuthorizationServiceImpl.findByToken(token, OAuth2TokenType.ACCESS_TOKEN);

            if(oAuth2Authorization != null) {
                oAuth2AuthorizationServiceImpl.remove(oAuth2Authorization);
            }

        } catch (Exception e) {
            response.put("logout", Boolean.FALSE);
            CustomUtils.createNonStoppableErrorMessage("로그 아웃 도중 오류 발생", e);
        }

        if(Objects.equals(response.get("logout"),Boolean.TRUE) && accessTokenUserInfo != null){
            pushAppTokenService.resetAppToken(accessTokenUserInfo.getAdditionalAccessTokenUserInfo().getId());
        }

        return new GlobalSuccessPayload<>(response);
    }

    @PreAuthorize("@authorityService.hasRole('CUSTOMER_ADMIN')")
    @GetMapping("/customers")
    public GlobalSuccessPayload<Page<CustomerResDTO.OneWithCountsWithAdmin>> getCustomersPage(@RequestParam(value = "skipPagination", required = false, defaultValue = "false") Boolean skipPagination,
                                                                                              @RequestParam(value = "pageNum", required = false, defaultValue = CommonConstant.COMMON_PAGE_NUM) Integer pageNum,
                                                                                              @RequestParam(value = "pageSize", required = false, defaultValue = CommonConstant.COMMON_PAGE_SIZE) Integer pageSize,
                                                                                              @RequestParam(value = "customerSearchFilter", required = false) String customerSearchFilter,
                                                                                              @RequestParam(value = "sorterValueFilter", required = false) String sorterValueFilter,
                                                                                              @RequestParam(value = "dateRangeFilter", required = false) String dateRangeFilter, @AuthenticationPrincipal AccessTokenUserInfo accessTokenUserInfo)
            throws JsonProcessingException, ResourceNotFoundException {

        return new GlobalSuccessPayload<>(customerService.getCustomersPage(skipPagination, pageNum, pageSize, customerSearchFilter, sorterValueFilter, dateRangeFilter));
    }

    @PreAuthorize("@authorityService.hasRole('CUSTOMER_ADMIN')")
    @PutMapping("/customers/{id}")
    public GlobalSuccessPayload<CustomerResDTO.Id> update(@PathVariable final long id, @Valid @RequestBody final CustomerReqDTO.Update dto)
            throws ResourceNotFoundException {
        return new GlobalSuccessPayload<>(customerService.update(id, dto));
    }

    @PreAuthorize("@authorityService.hasRole('CUSTOMER_ADMIN')")
    @PatchMapping("/customers/{id}/delete")
    public GlobalSuccessPayload<CustomerResDTO.IdAdminId> deleteCustomer(@PathVariable final long id, @AuthenticationPrincipal AccessTokenUserInfo accessTokenUserInfo) {

        customerService.deleteCustomer(id, accessTokenUserInfo.getAdditionalAccessTokenUserInfo().getId());

        return new GlobalSuccessPayload<>(new CustomerResDTO.IdAdminId(id, accessTokenUserInfo.getAdditionalAccessTokenUserInfo().getId()));
    }

    @PreAuthorize("@authorityService.hasRole('CUSTOMER_ADMIN')")
    @PatchMapping("/customers/{id}/restore")
    public GlobalSuccessPayload<CustomerResDTO.IdAdminId> restoreCustomer(@PathVariable final long id, @AuthenticationPrincipal AccessTokenUserInfo accessTokenUserInfo) {

        customerService.restoreCustomer(id);

        return new GlobalSuccessPayload<>(new CustomerResDTO.IdAdminId(id, accessTokenUserInfo.getAdditionalAccessTokenUserInfo().getId()));
    }

    @PreAuthorize("isAuthenticated()")
    @GetMapping("/customers/me/agrees")
    public GlobalSuccessPayload<CustomerResDTO.SensitiveInfoAgreeWithPushAgrees> getMeWithPushAgrees(@AuthenticationPrincipal AccessTokenUserInfo accessTokenUserInfo)
            throws ResourceNotFoundException {
        return new GlobalSuccessPayload<>(customerService.getMeWithPushAgrees(accessTokenUserInfo.getAdditionalAccessTokenUserInfo().getId()));
    }

    @PreAuthorize("isAuthenticated()")
    @PostMapping("/customers/me/agrees")
    public GlobalSuccessPayload<CustomerResDTO.Id> updateMeWithPushAgrees(@AuthenticationPrincipal AccessTokenUserInfo accessTokenUserInfo, @Valid @RequestBody final CustomerReqDTO.UpdateSensitiveInfoWithPushAgrees dto)
            throws ResourceNotFoundException {
        return new GlobalSuccessPayload<>(customerService.updateMeWithPushAgrees(accessTokenUserInfo.getAdditionalAccessTokenUserInfo().getId(), dto));
    }

    @PreAuthorize("isAuthenticated()")
    @PutMapping("/customers/me/update")
    public GlobalSuccessPayload<CustomerResDTO.Id> updateMePasswordAndEmail(@AuthenticationPrincipal AccessTokenUserInfo accessTokenUserInfo, @Valid @RequestBody final CustomerReqDTO.UpdatePasswordAndEmail dto)
            throws ResourceNotFoundException {
        return new GlobalSuccessPayload<>(customerService.updateMePasswordAndEmail(accessTokenUserInfo.getAdditionalAccessTokenUserInfo().getId(), dto));
    }
}
