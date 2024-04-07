package com.patternknife.securityhelper.oauth2.config.security.dao;

import com.patternknife.securityhelper.oauth2.config.database.CommonQuerydslRepositorySupport;
import com.patternknife.securityhelper.oauth2.config.security.entity.CustomOauthAccessToken;
import com.patternknife.securityhelper.oauth2.config.security.entity.QCustomOauthAccessToken;
import com.patternknife.securityhelper.oauth2.config.security.entity.QCustomOauthRefreshToken;
import com.patternknife.securityhelper.oauth2.domain.accesstokenhistory.dto.AccessTokenHistoryDTO;
import com.patternknife.securityhelper.oauth2.domain.accesstokenhistory.dto.AccessTokenHistorySearchFilter;
import com.patternknife.securityhelper.oauth2.domain.accesstokenhistory.dto.QAccessTokenHistoryDTO_AccessTokenWithCustomerRes;
import com.patternknife.securityhelper.oauth2.domain.common.dto.SorterValueFilter;
import com.patternknife.securityhelper.oauth2.domain.customer.entity.QCustomer;
import com.patternknife.securityhelper.oauth2.util.CustomUtils;
import com.patternknife.securityhelper.oauth2.util.PaginationUtil;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.querydsl.jpa.JPQLQuery;
import com.querydsl.jpa.impl.JPAQueryFactory;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.domain.Page;
import org.springframework.stereotype.Repository;


@Repository
public class CustomOauthAccessTokenRepositorySupport extends CommonQuerydslRepositorySupport {

    private final CustomOauthAccessTokenRepository customOauthAccessTokenRepository;
    private final JPAQueryFactory jpaQueryFactory;

    private EntityManager entityManager;

    public CustomOauthAccessTokenRepositorySupport(CustomOauthAccessTokenRepository customOauthAccessTokenRepository, @Qualifier("authJpaQueryFactory") JPAQueryFactory jpaQueryFactory) {
        super(CustomOauthAccessToken.class);
        this.customOauthAccessTokenRepository = customOauthAccessTokenRepository;
        this.jpaQueryFactory = jpaQueryFactory;
    }

    @Override
    @PersistenceContext(unitName = "commonEntityManager")
    public void setEntityManager(EntityManager entityManager) {
        super.setEntityManager(entityManager);
        this.entityManager = entityManager;
    }

    public Page<AccessTokenHistoryDTO.AccessTokenWithCustomerRes> findByPageAndFilterAndCustomerId(Boolean skipPagination,
                                                                                                   Integer pageNum,
                                                                                                   Integer pageSize,
                                                                                                   String accessTokenHistorySearchFilter,
                                                                                                   String sorterValueFilter,
                                                                                                   Long customerId) throws JsonProcessingException {

        final QCustomOauthAccessToken qCustomOauthAccessToken = QCustomOauthAccessToken.customOauthAccessToken;
        final QCustomOauthRefreshToken qCustomOauthRefreshToken = QCustomOauthRefreshToken.customOauthRefreshToken;

        final QCustomer qCustomer = QCustomer.customer;

        JPQLQuery<AccessTokenHistoryDTO.AccessTokenWithCustomerRes> query = jpaQueryFactory.select(new QAccessTokenHistoryDTO_AccessTokenWithCustomerRes(
                qCustomOauthAccessToken.authenticationId,
                qCustomOauthAccessToken.userName,
                qCustomOauthAccessToken.appToken,
                qCustomOauthAccessToken.userAgent,
                qCustomOauthAccessToken.remoteIp,
                qCustomer.id,
                qCustomOauthAccessToken.expirationDate,
                qCustomOauthRefreshToken.expirationDate,
                qCustomOauthAccessToken.createdAt,
                qCustomOauthAccessToken.updatedAt
                ))
                .from(qCustomOauthAccessToken)
                .leftJoin(qCustomer).on(qCustomer.idName.eq(qCustomOauthAccessToken.userName))
                .leftJoin(qCustomOauthRefreshToken).on(qCustomOauthAccessToken.refreshToken.eq(qCustomOauthRefreshToken.tokenId))
                .where(QCustomer.customer.id.eq(customerId));

        ObjectMapper objectMapper = new ObjectMapper();

        if(!CustomUtils.isEmpty(accessTokenHistorySearchFilter)) {
            AccessTokenHistorySearchFilter deserializedAccessTokenHistorySearchFilter = objectMapper.readValue(accessTokenHistorySearchFilter, AccessTokenHistorySearchFilter.class);
            if(!CustomUtils.isEmpty(deserializedAccessTokenHistorySearchFilter.getAppToken())){
                query.where(qCustomOauthAccessToken.appToken.likeIgnoreCase("%" + deserializedAccessTokenHistorySearchFilter.getAppToken() + "%"));
            }
            if(!CustomUtils.isEmpty(deserializedAccessTokenHistorySearchFilter.getRemoteIp())){
                query.where(qCustomOauthAccessToken.remoteIp.likeIgnoreCase("%" + deserializedAccessTokenHistorySearchFilter.getRemoteIp() + "%"));
            }
            if(!CustomUtils.isEmpty(deserializedAccessTokenHistorySearchFilter.getUserName())){
                query.where(qCustomOauthAccessToken.userName.likeIgnoreCase("%" + deserializedAccessTokenHistorySearchFilter.getUserName() + "%"));
            }
        }

        if(!CustomUtils.isEmpty(sorterValueFilter)) {
            SorterValueFilter deserializedSorterValueFilter = (SorterValueFilter) objectMapper.readValue(sorterValueFilter, SorterValueFilter.class);

            String sortedColumn = deserializedSorterValueFilter.getColumn();

            switch (sortedColumn) {
                case "userName":
                    query.orderBy(deserializedSorterValueFilter.getAsc() ? qCustomOauthAccessToken.userName.asc() : qCustomOauthAccessToken.userName.desc());
                    break;
                case "appToken":
                    query.orderBy(deserializedSorterValueFilter.getAsc() ? qCustomOauthAccessToken.appToken.asc() : qCustomOauthAccessToken.appToken.desc());
                    break;
                case "userAgent":
                    query.orderBy(deserializedSorterValueFilter.getAsc() ? qCustomOauthAccessToken.userAgent.asc() : qCustomOauthAccessToken.userAgent.desc());
                    break;
                case "remoteIp":
                    query.orderBy(deserializedSorterValueFilter.getAsc() ? qCustomOauthAccessToken.remoteIp.asc() : qCustomOauthAccessToken.remoteIp.desc());
                    break;
                case "accessTokenExpirationDate":
                    query.orderBy(deserializedSorterValueFilter.getAsc() ? qCustomOauthAccessToken.expirationDate.asc() : qCustomOauthAccessToken.expirationDate.desc());
                    break;
                case "refreshTokenExpirationDate":
                    query.orderBy(deserializedSorterValueFilter.getAsc() ? qCustomOauthRefreshToken.expirationDate.asc() : qCustomOauthRefreshToken.expirationDate.desc());
                    break;
                case "createdAt":
                    query.orderBy(deserializedSorterValueFilter.getAsc() ? qCustomOauthAccessToken.createdAt.asc() : qCustomOauthAccessToken.createdAt.desc());
                    break;
                case "updatedAt":
                    query.orderBy(deserializedSorterValueFilter.getAsc() ? qCustomOauthAccessToken.updatedAt.asc() : qCustomOauthAccessToken.updatedAt.desc());
                    break;
                default:
                    throw new IllegalArgumentException("다음은 유효한 정렬 컬럼이 아닙니다 : " + sortedColumn);
            }
        }

        PaginationUtil paginationUtil = new PaginationUtil(getQuerydsl());
        return paginationUtil.applyPagination(query, pageNum, pageSize, skipPagination);
    }
}
