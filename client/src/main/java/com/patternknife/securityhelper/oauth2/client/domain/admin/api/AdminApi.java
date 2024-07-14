package com.patternknife.securityhelper.oauth2.client.domain.admin.api;

import com.patternknife.securityhelper.oauth2.api.config.security.serivce.persistence.authorization.OAuth2AuthorizationServiceImpl;
import com.patternknife.securityhelper.oauth2.client.config.response.error.exception.data.ResourceNotFoundException;
import com.patternknife.securityhelper.oauth2.client.config.securityimpl.guard.AccessTokenUserInfo;

import com.patternknife.securityhelper.oauth2.client.domain.admin.dto.AdminDTO;
import com.patternknife.securityhelper.oauth2.client.domain.admin.entity.Admin;
import com.patternknife.securityhelper.oauth2.client.domain.admin.service.AdminService;
import com.patternknife.securityhelper.oauth2.client.util.CommonConstant;
import com.patternknife.securityhelper.oauth2.client.util.CustomUtils;
import com.fasterxml.jackson.core.JsonProcessingException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;
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
import java.util.Map;



@RestController
@RequestMapping("/api/v1")
@AllArgsConstructor
public class AdminApi {

    private final AdminService adminService;
    private final OAuth2AuthorizationServiceImpl authorizationService;


    @PreAuthorize("@resourceServerAuthorityChecker.hasAnyAdminRole()")
    @GetMapping("/admins/me")
    public AdminDTO.CurrentOneWithSessionRemainingSecondsRes getAdminSelf(@AuthenticationPrincipal AccessTokenUserInfo accessTokenUserInfo,
                                                @RequestHeader("Authorization") String authorizationHeader) throws ResourceNotFoundException {

        String token = authorizationHeader.substring("Bearer ".length());


        int accessTokenRemainingSeconds = 0;

        OAuth2Authorization oAuth2Authorization = authorizationService.findByToken(token, OAuth2TokenType.ACCESS_TOKEN);

        if(oAuth2Authorization != null) {
            OAuth2AccessToken oAuth2AccessToken = oAuth2Authorization.getAccessToken().getToken();

            if (oAuth2AccessToken != null) {
                Instant now = Instant.now();
                Instant expiresAt = oAuth2AccessToken.getExpiresAt();
                accessTokenRemainingSeconds = Math.toIntExact(Duration.between(now, expiresAt).getSeconds());

            }
        }

        return new AdminDTO.CurrentOneWithSessionRemainingSecondsRes(
                adminService.findAdminWithRoleIdsByAdminId(accessTokenUserInfo.getAdditionalAccessTokenUserInfo().getId()),
                accessTokenRemainingSeconds);

    }

    @PreAuthorize("@resourceServerAuthorityChecker.hasAnyAdminRole()")
    @GetMapping("/admin/me/logout")
    public Map<String, Boolean> logoutAdmin(HttpServletRequest request) {

        DefaultBearerTokenResolver resolver = new DefaultBearerTokenResolver();
        String token = resolver.resolve(request);

        Map<String, Boolean> response = new HashMap<>();

        response.put("logout", Boolean.TRUE);

        try {
            OAuth2Authorization oAuth2Authorization = authorizationService.findByToken(token, OAuth2TokenType.ACCESS_TOKEN);

            if(oAuth2Authorization != null) {
                authorizationService.remove(oAuth2Authorization);
            }

        } catch (Exception e) {
            response.put("logout", Boolean.FALSE);
            CustomUtils.createNonStoppableErrorMessage("Error during logout", e);
        }
        return response;
    }



    @PreAuthorize("hasAuthority('SUPER_ADMIN')")
    @GetMapping("/admins")
    public Page<AdminDTO.OneWithRoleIdsRes> getAdminList(@RequestParam(value = "skipPagination", required = false, defaultValue = "false") Boolean skipPagination,
                                                         @RequestParam(value = "pageNum", required = false, defaultValue = CommonConstant.COMMON_PAGE_NUM) Integer pageNum,
                                                         @RequestParam(value = "pageSize", required = false, defaultValue = CommonConstant.COMMON_PAGE_SIZE) Integer pageSize,
                                                         @RequestParam(value = "adminSearchFilter", required = false) String adminSearchFilter,
                                                         @RequestParam(value = "sorterValueFilter", required = false) String sorterValueFilter,
                                                         @RequestParam(value = "dateRangeFilter", required = false) String dateRangeFilter,
                                                         @AuthenticationPrincipal AccessTokenUserInfo accessTokenUserInfo)
            throws JsonProcessingException, ResourceNotFoundException {

        return adminService.findAdminsByPageRequest(skipPagination, pageNum, pageSize, adminSearchFilter, sorterValueFilter, dateRangeFilter, accessTokenUserInfo);
    }



    @PreAuthorize("hasAuthority('SUPER_ADMIN')")
    @GetMapping("/admins/{id}")
    public ResponseEntity<Admin> getAdminById(@PathVariable(value = "id") Long adminId, @AuthenticationPrincipal AccessTokenUserInfo accessTokenUserInfo)
            throws ResourceNotFoundException {

        Admin adminDTO = adminService.findById(adminId);

        return ResponseEntity.ok().body(adminDTO);

    }


    @PreAuthorize("hasAuthority('SUPER_ADMIN')")
    @PostMapping("/admins")
    public AdminDTO.CreateRes create(@Valid @RequestBody final AdminDTO.CreateReq dto){
        return new AdminDTO.CreateRes(adminService.create(dto));
    }

    @PreAuthorize("hasAuthority('SUPER_ADMIN')")
    @PutMapping("/admins/{id}")
    public AdminDTO.UpdateRes update(@PathVariable final long id, @Valid @RequestBody final AdminDTO.UpdateReq dto)
            throws ResourceNotFoundException {
        return adminService.update(id, dto);
    }

}
