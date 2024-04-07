package com.patternknife.securityhelper.oauth2.domain.admin.api;

import com.patternknife.securityhelper.oauth2.config.response.GlobalSuccessPayload;
import com.patternknife.securityhelper.oauth2.config.response.error.exception.data.ResourceNotFoundException;
import com.patternknife.securityhelper.oauth2.config.security.serivce.OAuth2AuthorizationServiceImpl;
import com.patternknife.securityhelper.oauth2.config.security.principal.AccessTokenUserInfo;
import com.patternknife.securityhelper.oauth2.domain.admin.dto.AdminDTO;
import com.patternknife.securityhelper.oauth2.domain.admin.entity.Admin;
import com.patternknife.securityhelper.oauth2.domain.admin.service.AdminService;
import com.patternknife.securityhelper.oauth2.util.CommonConstant;
import com.patternknife.securityhelper.oauth2.util.CustomUtils;
import com.fasterxml.jackson.core.JsonProcessingException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
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


/*
*   Admin 이 Admin 을 제어하는 API 들에 한해 SUPER_ADMIN 들만 가능하다.
* */
@RestController
@RequestMapping("/api/v1")
@AllArgsConstructor
public class AdminApi {

    private final AdminService adminService;
    private final OAuth2AuthorizationServiceImpl authorizationService;

    /* Admin 자기 자신 */

    @PreAuthorize("@authorityService.hasAnyAdminRole()")
    @GetMapping("/admins/me")
    public GlobalSuccessPayload<?> getAdminSelf(@AuthenticationPrincipal AccessTokenUserInfo accessTokenUserInfo,
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

        return new GlobalSuccessPayload<>(new AdminDTO.CurrentOneWithSessionRemainingSecondsRes(
                adminService.findAdminWithRoleIdsByAdminId(accessTokenUserInfo.getAdditionalAccessTokenUserInfo().getId()),
                accessTokenRemainingSeconds));

    }

    @PreAuthorize("@authorityService.hasAnyAdminRole()")
    @GetMapping("/admin/me/logout")
    public GlobalSuccessPayload<?> logoutAdmin(HttpServletRequest request,
                                               @AuthenticationPrincipal AccessTokenUserInfo accessTokenUserInfo) {

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
            CustomUtils.createNonStoppableErrorMessage("로그 아웃 도중 오류 발생", e);
        }
        return new GlobalSuccessPayload<>(response);
    }


    /* Admin 이 다른 Admin의 권한을 제어 */

    @PreAuthorize("hasAuthority('SUPER_ADMIN')")
    @GetMapping("/admins")
    public GlobalSuccessPayload<?> getAdminList(@RequestParam(value = "skipPagination", required = false, defaultValue = "false") Boolean skipPagination,
                                             @RequestParam(value = "pageNum", required = false, defaultValue = CommonConstant.COMMON_PAGE_NUM) Integer pageNum,
                                             @RequestParam(value = "pageSize", required = false, defaultValue = CommonConstant.COMMON_PAGE_SIZE) Integer pageSize,
                                             @RequestParam(value = "adminSearchFilter", required = false) String adminSearchFilter,
                                             @RequestParam(value = "sorterValueFilter", required = false) String sorterValueFilter,
                                             @RequestParam(value = "dateRangeFilter", required = false) String dateRangeFilter,
                                             @AuthenticationPrincipal AccessTokenUserInfo accessTokenUserInfo)
            throws JsonProcessingException, ResourceNotFoundException {

        return new GlobalSuccessPayload<>(adminService.findAdminsByPageRequest(skipPagination, pageNum, pageSize, adminSearchFilter, sorterValueFilter, dateRangeFilter, accessTokenUserInfo));
    }


    /*
    *   TO DO. 엔터티 리턴 금지
    * */
    @PreAuthorize("hasAuthority('SUPER_ADMIN')")
    @GetMapping("/admins/{id}")
    public GlobalSuccessPayload<ResponseEntity<Admin>> getAdminById(@PathVariable(value = "id") Long adminId, @AuthenticationPrincipal AccessTokenUserInfo accessTokenUserInfo)
            throws ResourceNotFoundException {

        Admin adminDTO = adminService.findById(adminId);

        return new GlobalSuccessPayload<>(ResponseEntity.ok().body(adminDTO));

    }


    @PreAuthorize("hasAuthority('SUPER_ADMIN')")
    @PostMapping("/admins")
    public GlobalSuccessPayload<AdminDTO.CreateRes> create(@Valid @RequestBody final AdminDTO.CreateReq dto){
        return new GlobalSuccessPayload<>(new AdminDTO.CreateRes(adminService.create(dto)));
    }

    @PreAuthorize("hasAuthority('SUPER_ADMIN')")
    @PutMapping("/admins/{id}")
    public GlobalSuccessPayload<AdminDTO.UpdateRes> update(@PathVariable final long id, @Valid @RequestBody final AdminDTO.UpdateReq dto)
            throws ResourceNotFoundException {
        return new GlobalSuccessPayload<>(adminService.update(id, dto));
    }

}
