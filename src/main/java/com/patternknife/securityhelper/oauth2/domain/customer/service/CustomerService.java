package com.patternknife.securityhelper.oauth2.domain.customer.service;


import com.patternknife.securityhelper.oauth2.config.database.SelectablePersistenceConst;
import com.patternknife.securityhelper.oauth2.config.response.error.exception.data.AlreadyExistsException;
import com.patternknife.securityhelper.oauth2.config.response.error.exception.data.ResourceNotFoundException;
import com.patternknife.securityhelper.oauth2.config.security.dao.CustomOauthAccessTokenRepository;
import com.patternknife.securityhelper.oauth2.config.security.dao.CustomOauthRefreshTokenRepository;
import com.patternknife.securityhelper.oauth2.config.security.entity.CustomOauthAccessToken;
import com.patternknife.securityhelper.oauth2.config.security.principal.AccessTokenUserInfo;
import com.patternknife.securityhelper.oauth2.domain.common.dto.DateRangeFilter;
import com.patternknife.securityhelper.oauth2.domain.common.dto.SorterValueFilter;
import com.patternknife.securityhelper.oauth2.domain.customer.dao.CustomerRepository;
import com.patternknife.securityhelper.oauth2.domain.customer.dao.CustomerRepositorySupport;
import com.patternknife.securityhelper.oauth2.domain.customer.dao.SensitiveInfoAgreeHistoryRepository;
import com.patternknife.securityhelper.oauth2.domain.customer.dto.CombinedCustomerConditionFilter;
import com.patternknife.securityhelper.oauth2.domain.customer.dto.CustomerReqDTO;
import com.patternknife.securityhelper.oauth2.domain.customer.dto.CustomerResDTO;
import com.patternknife.securityhelper.oauth2.domain.customer.dto.CustomerSearchFilter;
import com.patternknife.securityhelper.oauth2.domain.customer.entity.Customer;
import com.patternknife.securityhelper.oauth2.domain.point.dao.PointDetailRepositorySupport;
import com.patternknife.securityhelper.oauth2.domain.push.dao.PushAgreeHistoryRepository;
import com.patternknife.securityhelper.oauth2.domain.push.dao.PushAgreeRepository;
import com.patternknife.securityhelper.oauth2.domain.push.entity.PushAgree;
import com.patternknife.securityhelper.oauth2.domain.socialoauth.service.SocialCustomTokenService;
import com.patternknife.securityhelper.oauth2.mapper.CustomerMapper;
import com.patternknife.securityhelper.oauth2.util.CustomUtils;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;


/*
 *
 *   Service 에서는,
 *
 *   1) CRUD 아닌 비즈니스 로직이 있는 경우 : bo 사용
 *   2) 다른 repository 들 여기에서 호출 가능
 *
 * */
@Service
@RequiredArgsConstructor
public class CustomerService  {

    private final CustomerRepository customerRepository;

    private final CustomerRepositorySupport customerRepositorySupport;
    private final PointDetailRepositorySupport pointDetailRepositorySupport;
    private final SocialCustomTokenService socialCustomTokenService;
    private final CustomerMapper customerMapper;

    private final CustomOauthAccessTokenRepository customOauthAccessTokenRepository;
    private final CustomOauthRefreshTokenRepository customOauthRefreshTokenRepository;

    private final PushAgreeHistoryRepository pushAgreeHistoryRepository;
    private final PushAgreeRepository pushAgreeRepository;
    private final SensitiveInfoAgreeHistoryRepository sensitiveInfoAgreeHistoryRepository;

    @Value("${spring.jpa.properties.hibernate.dialect}")
    String dbDialect;

    @Value("${app.oauth2.appUser.clientId}")
    private final String appUserClientId;

    public CustomerResDTO.OneWithResources findCustomerOneWithResources(Long id) {

        Long pointDetailTableSum = pointDetailRepositorySupport.findPointDetailsSumByCustomerId(id);

        CustomerResDTO.OneWithResources currentOneWithResource = customerRepositorySupport.findWithResources(id);
        if(currentOneWithResource == null){
            throw new ResourceNotFoundException("접속한 사용자의 정보가 확인되지 않습니다. 다시 로그인 요청드리며, 문제가 지속될 경우 관리자에게 문의 주십시오. (ID : " +  id + ")");
        }

        currentOneWithResource.setPoint(pointDetailTableSum);

        return currentOneWithResource;
    }

    public CustomerResDTO.OneWithInterestedTreatmentParts findCustomerOneWithInterestedTreatmentParts(String username) throws JsonProcessingException {
        return customerRepositorySupport.findWithInterestedTreatmentParts(username);
    }

    /*
    *   관리자에 의한 회원 중지
    * */
    @Transactional(value = "commonTransactionManager", rollbackFor=Exception.class)
    public void deleteCustomer(Long id, Long adminId){
        Customer customer = customerRepositorySupport.findById(id);

        List<CustomOauthAccessToken> customOauthAccessTokens = customOauthAccessTokenRepository.findByClientIdAndUserName(appUserClientId, customer.getIdName());

        for (CustomOauthAccessToken customOauthAccessToken : customOauthAccessTokens) {
            customOauthRefreshTokenRepository.deleteById(customOauthAccessToken.getRefreshToken());
        }

        customOauthAccessTokenRepository.deleteByUserName(customer.getIdName());

        customerRepositorySupport.deleteOne(id, adminId);
    }

    /*
    *   회원 탈퇴
    * */
    @Transactional(value = "commonTransactionManager", rollbackFor=Exception.class)
    public void deleteCustomer(AccessTokenUserInfo accessTokenUserInfo){

        Customer customer = customerRepositorySupport.findById(accessTokenUserInfo.getAdditionalAccessTokenUserInfo().getId());

        List<CustomOauthAccessToken> customOauthAccessTokens = customOauthAccessTokenRepository.findByClientIdAndUserName(appUserClientId, customer.getIdName());

        for (CustomOauthAccessToken customOauthAccessToken : customOauthAccessTokens) {
            customOauthRefreshTokenRepository.deleteById(customOauthAccessToken.getRefreshToken());
        }

        customOauthAccessTokenRepository.deleteByUserName(customer.getIdName());

        // 회원 탈퇴의 기준은 deleted_at, deleted_ci 컬럼에 값이 있는 경우이다. 그리고 이러한 사용자는 탈퇴한 회원이므로 관리자가 복원 불가하다.
        customer.setDeletedAt(LocalDateTime.now());
        // 계정 비활성화의 기준은 deleted_at, delete_admin_id 에 값이 있는 경우이며, 관리자가 복원 가능하다. 여기는 회원 탈퇴 로직이므로 delete_admin_id 를 항상 null 로 만들어 준다.
        customer.setDeleteAdmin(null);

        // 하기 건들은 탈퇴한 회원들의 unique key 들이므로 충돌 방지를 위해 삭제
        customer.setDeletedCi(customer.getCi());
        customer.setCi(null);

        customer.setDeletedIdName(customer.getIdName());
        customer.setIdName(null);

        customer.setDeletedKakaoIdName(customer.getKakaoIdName());
        customer.setKakaoIdName(null);

        customer.setDeletedNaverIdName(customer.getNaverIdName());
        customer.setNaverIdName(null);

        customer.setDeletedAppleIdName(customer.getDeletedNaverIdName());
        customer.setAppleIdName(null);

    }

    @Transactional(value = "commonTransactionManager", rollbackFor=Exception.class)
    public void restoreCustomer(Long id){
        customerRepositorySupport.restoreOne(id);
    }


    @Transactional(value = "commonTransactionManager" ,readOnly = true)
    public Page<CustomerResDTO.OneWithCountsWithAdmin> getCustomersPage(Boolean skipPagination,
                                                                        Integer pageNum,
                                                                        Integer pageSize,
                                                                        String customerSearchFilter,
                                                                        String sorterValueFilter,
                                                                        String dateRangeFilter) throws JsonProcessingException {

        CombinedCustomerConditionFilter combinedCustomerConditionFilter = new CombinedCustomerConditionFilter();

        ObjectMapper objectMapper = new ObjectMapper();

        if(!CustomUtils.isEmpty(customerSearchFilter)) {
            CustomerSearchFilter deserializedCustomerSearchFilter = (CustomerSearchFilter) objectMapper.readValue(customerSearchFilter, CustomerSearchFilter.class);
            combinedCustomerConditionFilter.setCustomerSearchFilter(deserializedCustomerSearchFilter);
        }
        if(!CustomUtils.isEmpty(dateRangeFilter)) {
            DateRangeFilter deserializedDateRangeFilter = (DateRangeFilter) objectMapper.readValue(dateRangeFilter, DateRangeFilter.class);
            if (deserializedDateRangeFilter.getEndDate() != null &&
                    !deserializedDateRangeFilter.getEndDate().matches(".*\\d{2}:\\d{2}:\\d{2}$")) {
                String newEndDate = deserializedDateRangeFilter.getEndDate() + "T23:59:59";
                deserializedDateRangeFilter.setEndDate(newEndDate);
            }
            combinedCustomerConditionFilter.setDateRangeFilter(deserializedDateRangeFilter);
        }
        if(!CustomUtils.isEmpty(sorterValueFilter)) {
            SorterValueFilter deserializedSorterValueFilter = (SorterValueFilter) objectMapper.readValue(sorterValueFilter, SorterValueFilter.class);
            combinedCustomerConditionFilter.setSorterValueFilter(deserializedSorterValueFilter);
        }

        int offset = (pageNum - 1) * pageSize;
        int limit = pageSize;

        List<CustomerResDTO.OneWithCountsWithAdmin> customers = customerMapper.findByPageFilter(combinedCustomerConditionFilter,
                limit, offset, dbDialect.equals(SelectablePersistenceConst.MYSQL_8.getValue()));

        int total = customerMapper.countByPageFilter(combinedCustomerConditionFilter);

        return new PageImpl<>(customers, PageRequest.of(pageNum - 1, pageSize), total);
    }



    /*
        2. 사용자 생성
    * */
    public CustomerResDTO.IdWithTokenResponse create(CustomerReqDTO.Create dto) {
        if (customerRepository.existsByNameAndHpAndBirthdayAndSex(dto.getName(),dto.getHp(),dto.getBirthday(),dto.getSex())) {
            throw new AlreadyExistsException("중복된 고객이 있습니다(이름, hp, 생일, 성별)");
        }

        Customer justNowCreatedCustomer = customerRepositorySupport.createNonSocialUser(dto);

        return new CustomerResDTO.IdWithTokenResponse(justNowCreatedCustomer, socialCustomTokenService.createAccessToken(justNowCreatedCustomer, appUserClientId));
    }

    @Transactional(value = "commonTransactionManager", rollbackFor=Exception.class)
    public CustomerResDTO.Id update(Long id, CustomerReqDTO.Update dto) {
        return customerRepositorySupport.updateOne(id, dto);
    }

    public List<CustomerResDTO.IdNamesCreatedAt> findIdNameByNameWithHp(String name, String hp) {
        List<Customer> foundCustomers = customerRepository.findByNameAndHp(name, CustomUtils.removeSpecialCharacters(hp)).orElse(Collections.emptyList());
        return foundCustomers.stream().map(CustomerResDTO.IdNamesCreatedAt::new).collect(Collectors.toList());
    }

    public boolean checkIdNameDuplicate(String idName) {
        return customerRepository.existsByIdName(idName);
    }

    public boolean checkHpDuplicate(String hp) {
        return customerRepository.existsByHp(CustomUtils.removeSpecialCharacters(hp));
    }

    public CustomerResDTO.SensitiveInfoAgreeWithPushAgrees getMeWithPushAgrees(Long customerId) {
        return customerRepositorySupport.findOneWithPushAgreesById(customerId);
    }

    @Transactional(value = "commonTransactionManager", rollbackFor=Exception.class)
    public CustomerResDTO.Id updateMeWithPushAgrees(Long id, CustomerReqDTO.UpdateSensitiveInfoWithPushAgrees dto) {
        Customer customer = customerRepository.findById(id).orElseThrow(() -> new ResourceNotFoundException("해당 고객 ID ('" + id + "') 를 찾을 수 없습니다."));
        PushAgree pushAgree = pushAgreeRepository.findFirstByCustomerIdOrderByCreatedAtDesc(id);

        if (pushAgree != null) {
            pushAgree = dto.toEntity(pushAgree);
        } else {
            pushAgree = dto.toEntity(customer);
        }

        pushAgreeRepository.save(pushAgree);
        pushAgreeHistoryRepository.save(dto.toPushAgreeHistoryEntity(customer.getId()));

        sensitiveInfoAgreeHistoryRepository.save(dto.toSensitiveInfoAgreeHistoryEntity(customer.getId()));
        return customerRepositorySupport.updateMeWithPushAgrees(customer, dto);
    }

    @Transactional(value = "commonTransactionManager", rollbackFor=Exception.class)
    public CustomerResDTO.Id updateMePasswordAndEmail(Long id, CustomerReqDTO.UpdatePasswordAndEmail dto) {
        Customer customer = customerRepository.findById(id).orElseThrow(() -> new ResourceNotFoundException("해당 고객 ID ('" + id + "') 를 찾을 수 없습니다."));
        customerRepositorySupport.updateMePasswordAndEmail(customer, dto);
        return new CustomerResDTO.Id(customer);
    }

}