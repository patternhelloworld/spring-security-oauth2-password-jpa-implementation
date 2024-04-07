package com.patternknife.securityhelper.oauth2.config.security.dao;

import com.patternknife.securityhelper.oauth2.config.database.CommonQuerydslRepositorySupport;
import com.patternknife.securityhelper.oauth2.config.security.entity.OauthAccessTokenRecord;
import com.patternknife.securityhelper.oauth2.config.security.entity.QOauthAccessTokenRecord;
import com.patternknife.securityhelper.oauth2.config.security.enums.MobileOSType;
import com.patternknife.securityhelper.oauth2.domain.accesstokenhistory.dto.AccessTokenHistoryDTO;
import com.patternknife.securityhelper.oauth2.domain.accesstokenhistory.dto.AccessTokenRecordHistorySearchFilter;
import com.patternknife.securityhelper.oauth2.domain.accesstokenhistory.dto.QAccessTokenHistoryDTO_AccessTokenRecordWithCustomerRes;
import com.patternknife.securityhelper.oauth2.domain.common.dto.DateRangeFilter;
import com.patternknife.securityhelper.oauth2.domain.common.dto.SorterValueFilter;
import com.patternknife.securityhelper.oauth2.domain.customer.dao.CustomerRepositorySupport;
import com.patternknife.securityhelper.oauth2.domain.customer.entity.Customer;
import com.patternknife.securityhelper.oauth2.domain.statistics.dto.QStatisticsDTO_NonPeriodicOne;
import com.patternknife.securityhelper.oauth2.domain.statistics.dto.StatisticsDTO;
import com.patternknife.securityhelper.oauth2.util.CustomUtils;
import com.patternknife.securityhelper.oauth2.util.PaginationUtil;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.querydsl.core.BooleanBuilder;
import com.querydsl.core.types.dsl.CaseBuilder;
import com.querydsl.jpa.JPQLQuery;
import com.querydsl.jpa.impl.JPAQueryFactory;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.domain.Page;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.util.List;

@Repository
public class OauthAccessTokenRecordRepositorySupport extends CommonQuerydslRepositorySupport {

    private final OauthAccessTokenRecordRepository oauthAccessTokenRecordRepository;
    private final CustomerRepositorySupport customerRepositorySupport;

    private final JPAQueryFactory jpaQueryFactory;

    private EntityManager entityManager;

    public OauthAccessTokenRecordRepositorySupport(OauthAccessTokenRecordRepository oauthAccessTokenRecordRepository,
                                                   CustomerRepositorySupport customerRepositorySupport,
                                                   @Qualifier("authJpaQueryFactory") JPAQueryFactory jpaQueryFactory) {
        super(OauthAccessTokenRecord.class);
        this.oauthAccessTokenRecordRepository = oauthAccessTokenRecordRepository;
        this.customerRepositorySupport = customerRepositorySupport;
        this.jpaQueryFactory = jpaQueryFactory;
    }

    @Override
    @PersistenceContext(unitName = "commonEntityManager")
    public void setEntityManager(EntityManager entityManager) {
        super.setEntityManager(entityManager);
        this.entityManager = entityManager;
    }

    public Page<AccessTokenHistoryDTO.AccessTokenRecordWithCustomerRes> findByPageAndFilterAndCustomerId(Boolean skipPagination,
                                                                                                         Integer pageNum,
                                                                                                         Integer pageSize,
                                                                                                         String accessTokenRecordHistorySearchFilter,
                                                                                                         String sorterValueFilter,
                                                                                                         Long customerId) throws JsonProcessingException {

        final QOauthAccessTokenRecord qOauthAccessTokenRecord = QOauthAccessTokenRecord.oauthAccessTokenRecord;

        Customer customer = customerRepositorySupport.findById(customerId);

        JPQLQuery<AccessTokenHistoryDTO.AccessTokenRecordWithCustomerRes> query = jpaQueryFactory.select(new
                        QAccessTokenHistoryDTO_AccessTokenRecordWithCustomerRes(
                        qOauthAccessTokenRecord.userName,
                        qOauthAccessTokenRecord.userAgent,qOauthAccessTokenRecord.createdAt, qOauthAccessTokenRecord.updatedAt))
                .from(qOauthAccessTokenRecord)
                .where(qOauthAccessTokenRecord.userName.eq(customer.getIdName()));

        ObjectMapper objectMapper = new ObjectMapper();

        if(!CustomUtils.isEmpty(accessTokenRecordHistorySearchFilter)) {
            AccessTokenRecordHistorySearchFilter deserializedAccessTokenRecordHistorySearchFilter = objectMapper.readValue(accessTokenRecordHistorySearchFilter, AccessTokenRecordHistorySearchFilter.class);
            if(!CustomUtils.isEmpty(deserializedAccessTokenRecordHistorySearchFilter.getUserName())){
                query.where(qOauthAccessTokenRecord.userName.likeIgnoreCase("%" + deserializedAccessTokenRecordHistorySearchFilter.getUserName() + "%"));
            }
            if(!CustomUtils.isEmpty(deserializedAccessTokenRecordHistorySearchFilter.getUserAgent())){
                query.where(qOauthAccessTokenRecord.userAgent.likeIgnoreCase("%" + deserializedAccessTokenRecordHistorySearchFilter.getUserAgent() + "%"));
            }
        }

        if(!CustomUtils.isEmpty(sorterValueFilter)) {
            SorterValueFilter deserializedSorterValueFilter = (SorterValueFilter) objectMapper.readValue(sorterValueFilter, SorterValueFilter.class);

            String sortedColumn = deserializedSorterValueFilter.getColumn();

            switch (sortedColumn) {
                case "userName":
                    query.orderBy(deserializedSorterValueFilter.getAsc() ? qOauthAccessTokenRecord.userName.asc() : qOauthAccessTokenRecord.userName.desc());
                    break;
                case "userAgent":
                    query.orderBy(deserializedSorterValueFilter.getAsc() ? qOauthAccessTokenRecord.userAgent.asc() : qOauthAccessTokenRecord.userAgent.desc());
                    break;
                case "createdAt":
                    query.orderBy(deserializedSorterValueFilter.getAsc() ? qOauthAccessTokenRecord.createdAt.asc() : qOauthAccessTokenRecord.createdAt.desc());
                    break;
                case "updatedAt":
                    query.orderBy(deserializedSorterValueFilter.getAsc() ? qOauthAccessTokenRecord.updatedAt.asc() : qOauthAccessTokenRecord.updatedAt.desc());
                    break;
                default:
                    throw new IllegalArgumentException("다음은 유효한 정렬 컬럼이 아닙니다 : " + sortedColumn);
            }
        }

        PaginationUtil paginationUtil = new PaginationUtil(getQuerydsl());
        return paginationUtil.applyPagination(query, pageNum, pageSize, skipPagination);
    }

    public List<StatisticsDTO.NonPeriodicOne> findOauthAccessTokenRecordsDeviceType(String dateRangeFilter) throws JsonProcessingException {

        final QOauthAccessTokenRecord qOauthAccessTokenRecord = QOauthAccessTokenRecord.oauthAccessTokenRecord;

        JPQLQuery<StatisticsDTO.NonPeriodicOne> query = jpaQueryFactory
                .select(new QStatisticsDTO_NonPeriodicOne(
                        new CaseBuilder()
                                .when(qOauthAccessTokenRecord.deviceType.eq(MobileOSType.ANDROID.getValue())).then(MobileOSType.ANDROID.name())
                                .when(qOauthAccessTokenRecord.deviceType.eq(MobileOSType.IOS.getValue())).then(MobileOSType.IOS.name())
                                .otherwise(""),
                        qOauthAccessTokenRecord.deviceType.count())
                )
                .from(qOauthAccessTokenRecord)
                .where(qOauthAccessTokenRecord.deviceType.in(MobileOSType.ANDROID.getValue(), MobileOSType.IOS.getValue()));

        ObjectMapper objectMapper = new ObjectMapper();
        if (!CustomUtils.isEmpty(dateRangeFilter)) {
            DateRangeFilter deserializedDateRangeFilter = (DateRangeFilter) objectMapper.readValue(dateRangeFilter, DateRangeFilter.class);
            if (!CustomUtils.isEmpty(deserializedDateRangeFilter.getColumn())) {
                if ("createdAt".equals(deserializedDateRangeFilter.getColumn())) {

                    BooleanBuilder booleanBuilder = new BooleanBuilder();

                    if (!CustomUtils.isEmpty(deserializedDateRangeFilter.getStartDate())) {
                        Timestamp startTimestamp = Timestamp.valueOf(deserializedDateRangeFilter.getStartDate() + " 00:00:00");
                        booleanBuilder.and(qOauthAccessTokenRecord.createdAt.after(startTimestamp));
                    }
                    if (!CustomUtils.isEmpty(deserializedDateRangeFilter.getEndDate())) {
                        Timestamp endTimestamp = Timestamp.valueOf(deserializedDateRangeFilter.getEndDate() + " 23:59:59");
                        booleanBuilder.and(qOauthAccessTokenRecord.createdAt.before(endTimestamp));
                    }
                    query.where(booleanBuilder);
                } else {
                    throw new IllegalStateException("유효하지 않은 Date range 검색 대상입니다.");
                }
            }

        }
        return query.groupBy(qOauthAccessTokenRecord.deviceType).fetch();
    }

}
