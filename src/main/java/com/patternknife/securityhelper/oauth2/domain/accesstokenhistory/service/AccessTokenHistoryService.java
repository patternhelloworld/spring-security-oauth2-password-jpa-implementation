package com.patternknife.securityhelper.oauth2.domain.accesstokenhistory.service;

import com.patternknife.securityhelper.oauth2.config.security.dao.CustomOauthAccessTokenRepositorySupport;
import com.patternknife.securityhelper.oauth2.config.security.dao.OauthAccessTokenRecordRepositorySupport;
import com.patternknife.securityhelper.oauth2.domain.accesstokenhistory.dto.AccessTokenHistoryDTO;
import com.fasterxml.jackson.core.JsonProcessingException;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.stereotype.Service;

import java.text.ParseException;

@Service
@RequiredArgsConstructor
public class AccessTokenHistoryService {

    private final CustomOauthAccessTokenRepositorySupport customOauthAccessTokenRepositorySupport;
    private final OauthAccessTokenRecordRepositorySupport oauthAccessTokenRecordRepositorySupport;

    public Page<AccessTokenHistoryDTO.AccessTokenWithCustomerRes> getAccessTokensPage(Boolean skipPagination, Integer pageNum, Integer pageSize, String accessTokenHistorySearchFilter, String sorterValueFilter, Long customerId) throws JsonProcessingException, ParseException {
        return customOauthAccessTokenRepositorySupport.findByPageAndFilterAndCustomerId(skipPagination,pageNum,pageSize,accessTokenHistorySearchFilter, sorterValueFilter, customerId);
    }

    public Page<AccessTokenHistoryDTO.AccessTokenRecordWithCustomerRes> getAccessTokenRecordsPage(Boolean skipPagination, Integer pageNum, Integer pageSize, String accessTokenRecordHistorySearchFilter, String sorterValueFilter, Long customerId) throws JsonProcessingException, ParseException {
        return oauthAccessTokenRecordRepositorySupport.findByPageAndFilterAndCustomerId(skipPagination,pageNum,pageSize,accessTokenRecordHistorySearchFilter, sorterValueFilter, customerId);
    }
}
