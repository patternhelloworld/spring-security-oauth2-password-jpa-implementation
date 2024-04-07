package com.patternknife.securityhelper.oauth2.domain.accesstokenhistory.api;

import com.patternknife.securityhelper.oauth2.config.response.GlobalSuccessPayload;
import com.patternknife.securityhelper.oauth2.domain.accesstokenhistory.dto.AccessTokenHistoryDTO;
import com.patternknife.securityhelper.oauth2.domain.accesstokenhistory.service.AccessTokenHistoryService;
import com.patternknife.securityhelper.oauth2.util.CommonConstant;
import com.fasterxml.jackson.core.JsonProcessingException;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.text.ParseException;

@RestController
@RequestMapping("/api/v1")
@RequiredArgsConstructor
public class AccessTokenHistoryApi {
    private final AccessTokenHistoryService accessTokenHistoryService;

    @PreAuthorize("hasAuthority('SUPER_ADMIN') or hasAuthority('CUSTOMER_ADMIN')")
    @GetMapping("/access-token-history/access-tokens/customers/{customerId}")
    public GlobalSuccessPayload<Page<AccessTokenHistoryDTO.AccessTokenWithCustomerRes>> getAccessTokensPage(@RequestParam(value = "skipPagination", required = false, defaultValue = "false") final Boolean skipPagination,
                                                                                                            @RequestParam(value = "pageNum", required = false, defaultValue = CommonConstant.COMMON_PAGE_NUM) final Integer pageNum,
                                                                                                            @RequestParam(value = "pageSize", required = false, defaultValue = CommonConstant.COMMON_PAGE_SIZE) final Integer pageSize,
                                                                                                            @RequestParam(value = "accessTokenHistorySearchFilter", required = false) final String accessTokenHistorySearchFilter,
                                                                                                            @RequestParam(value = "sorterValueFilter", required = false) final String sorterValueFilter,
                                                                                                            @PathVariable final long customerId)
    throws JsonProcessingException, ParseException {
        return new GlobalSuccessPayload<>(accessTokenHistoryService.getAccessTokensPage(skipPagination, pageNum, pageSize, accessTokenHistorySearchFilter, sorterValueFilter, customerId));
    }

    @PreAuthorize("hasAuthority('SUPER_ADMIN') or hasAuthority('CUSTOMER_ADMIN')")
    @GetMapping("/access-token-history/access-token-records/customers/{customerId}")
    public GlobalSuccessPayload<Page<AccessTokenHistoryDTO.AccessTokenRecordWithCustomerRes>> getAccessTokenRecordsPage(@RequestParam(value = "skipPagination", required = false, defaultValue = "false") final Boolean skipPagination,
                                                                                                                  @RequestParam(value = "pageNum", required = false, defaultValue = CommonConstant.COMMON_PAGE_NUM) final Integer pageNum,
                                                                                                                  @RequestParam(value = "pageSize", required = false, defaultValue = CommonConstant.COMMON_PAGE_SIZE) final Integer pageSize,
                                                                                                                  @RequestParam(value = "accessTokenRecordHistorySearchFilter", required = false) final String accessTokenRecordHistorySearchFilter,
                                                                                                                  @RequestParam(value = "sorterValueFilter", required = false) final String sorterValueFilter,
                                                                                                                  @PathVariable final long customerId)
            throws JsonProcessingException, ParseException {
        return new GlobalSuccessPayload<>(accessTokenHistoryService.getAccessTokenRecordsPage(skipPagination, pageNum, pageSize, accessTokenRecordHistorySearchFilter, sorterValueFilter, customerId));
    }
}
