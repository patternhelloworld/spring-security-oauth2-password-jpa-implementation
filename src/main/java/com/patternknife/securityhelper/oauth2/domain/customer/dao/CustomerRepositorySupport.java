package com.patternknife.securityhelper.oauth2.domain.customer.dao;

import com.patternknife.securityhelper.oauth2.config.database.CommonQuerydslRepositorySupport;
import com.patternknife.securityhelper.oauth2.config.database.SelectablePersistenceConst;
import com.patternknife.securityhelper.oauth2.config.response.error.exception.auth.UserRestoredException;
import com.patternknife.securityhelper.oauth2.config.response.error.exception.data.ResourceNotFoundException;
import com.patternknife.securityhelper.oauth2.domain.admin.dao.AdminRepositorySupport;
import com.patternknife.securityhelper.oauth2.domain.admin.entity.Admin;
import com.patternknife.securityhelper.oauth2.domain.common.dto.DateRangeFilter;
import com.patternknife.securityhelper.oauth2.domain.customer.dto.*;
import com.patternknife.securityhelper.oauth2.domain.customer.dto.CustomerReqDTO;
import com.patternknife.securityhelper.oauth2.domain.customer.dto.CustomerResDTO;
import com.patternknife.securityhelper.oauth2.domain.customer.entity.Customer;
import com.patternknife.securityhelper.oauth2.domain.customer.entity.QCustomer;
import com.patternknife.securityhelper.oauth2.domain.customergift.entity.QCustomerGift;
import com.patternknife.securityhelper.oauth2.domain.customergift.enums.CustomerGiftRequestStatus;
import com.patternknife.securityhelper.oauth2.domain.gift.entity.QGift;
import com.patternknife.securityhelper.oauth2.domain.interestedtreatmentpart.entity.QInterestedTreatmentPart;
import com.patternknife.securityhelper.oauth2.domain.point.dao.PointDetailRepository;
import com.patternknife.securityhelper.oauth2.domain.point.dto.PointDetailReqDTO;
import com.patternknife.securityhelper.oauth2.domain.point.enums.PointDetailStatus;
import com.patternknife.securityhelper.oauth2.domain.push.entity.QPushAgree;
import com.patternknife.securityhelper.oauth2.domain.socialoauth.dto.SocialVendorOauthDTO;
import com.patternknife.securityhelper.oauth2.domain.socialoauth.dto.SpringSecuritySocialOauthDTO;
import com.patternknife.securityhelper.oauth2.domain.socialoauth.dto.apple.AppleUserInfo;
import com.patternknife.securityhelper.oauth2.domain.statistics.dto.*;
import com.patternknife.securityhelper.oauth2.domain.statistics.enums.TimePeriod;
import com.patternknife.securityhelper.oauth2.domain.statistics.util.TimePeriodUtils;
import com.patternknife.securityhelper.oauth2.domain.treatment.entity.QTreatment;
import com.patternknife.securityhelper.oauth2.util.CustomUtils;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.querydsl.core.BooleanBuilder;
import com.querydsl.core.types.dsl.*;
import com.querydsl.jpa.JPQLQuery;
import com.querydsl.jpa.impl.JPAQueryFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.sql.Timestamp;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;

import static com.querydsl.core.types.dsl.Expressions.stringTemplate;

/*
 *
 *   QueryDsl 을 써야하는 경우 = 다른 엔터티들 Join, Group by, having... + 동적 where
 *
 *   RepositorySupport 에서는 다른 Repository 호출 가능
 * */
@Repository
public class CustomerRepositorySupport extends CommonQuerydslRepositorySupport {

    private final JPAQueryFactory jpaQueryFactory;

    private final CustomerRepository customerRepository;
    private final AdminRepositorySupport adminRepositorySupport;

    private final PointDetailRepository pointDetailRepository;
    private final String dbDialect;

    public CustomerRepositorySupport(@Qualifier("authJpaQueryFactory") JPAQueryFactory jpaQueryFactory, CustomerRepository customerRepository,
                                     AdminRepositorySupport adminRepositorySupport, PointDetailRepository pointDetailRepository,
                                     @Value("${spring.jpa.properties.hibernate.dialect}") String dbDialect) {

        super(Customer.class);
        this.customerRepository = customerRepository;
        this.adminRepositorySupport = adminRepositorySupport;
        this.pointDetailRepository = pointDetailRepository;
        this.jpaQueryFactory = jpaQueryFactory;
        this.dbDialect = dbDialect;
    }


    public Customer findById(Long id) throws ResourceNotFoundException {
        return customerRepository.findById(id).orElseThrow(() -> new ResourceNotFoundException("해당 ID의 사용자는 삭제 되었습니다 :: " + id));
    }

    public Customer findPointExpirationCheckedNullOrOldestFirst() {
        LocalDateTime oneHourBeforeLocalDateTime = LocalDateTime.now().minusHours(1);
        if (dbDialect.equals(SelectablePersistenceConst.MYSQL_8.getValue())) {
            return customerRepository.findPointExpirationCheckedNullOrOldestFirstMySQL(oneHourBeforeLocalDateTime).orElse(null);
        } else {
            return customerRepository.findPointExpirationCheckedNullOrOldestFirstMSSQL(oneHourBeforeLocalDateTime).orElse(null);
        }
    }

    /*
     *   TO DO. Customer 객체에 저장 된 point_details 테이블을 참조해서 지속적으로 동기화 하는 로직 필요.
     * */
    public CustomerResDTO.OneWithResources findWithResources(Long id) {

        final QCustomer qCustomer = QCustomer.customer;
        final QTreatment qTreatment = QTreatment.treatment;
        final QGift qGift = QGift.gift;
        final QCustomerGift qCustomerGift = QCustomerGift.customerGift;

        return jpaQueryFactory
                .select(new QCustomerResDTO_OneWithResources(qCustomer.id, qCustomer.idName,
                        qCustomer.email, qCustomer.name,
                        qCustomer.hp,
                        qCustomer.currentPoint,
                        qCustomerGift.countDistinct(),
                        qTreatment.countDistinct(),
                        qCustomer.createdAt, qCustomer.updatedAt
                ))
                .from(qCustomer)
                // OneToMany
                .leftJoin(qCustomer.customerGifts, qCustomerGift).on(qCustomerGift.requestStatus.eq(CustomerGiftRequestStatus.승인.getValue()))
                .leftJoin(qCustomerGift.gift, qGift)
                .leftJoin(qCustomer.treatments, qTreatment)
                .groupBy(qCustomer.id, qCustomer.idName,
                        qCustomer.email, qCustomer.name,
                        qCustomer.hp,
                        qCustomer.currentPoint,
                        qCustomer.createdAt, qCustomer.updatedAt)
                .where(qCustomer.id.eq(id)).fetchOne();

    }

    public CustomerResDTO.OneWithInterestedTreatmentParts findWithInterestedTreatmentParts(String username) throws JsonProcessingException {

        final QCustomer qCustomer = QCustomer.customer;
        final QInterestedTreatmentPart qInterestedTreatmentPart = QInterestedTreatmentPart.interestedTreatmentPart;

        return jpaQueryFactory
                .select(new QCustomerResDTO_OneWithInterestedTreatmentParts(qCustomer.id, qInterestedTreatmentPart.id, qInterestedTreatmentPart.upperPart,
                        qInterestedTreatmentPart.middlePart, qInterestedTreatmentPart.lowerPart, qCustomer.createdAt, qCustomer.updatedAt
                ))
                .from(qCustomer)
                // OneToMany
                .leftJoin(qCustomer.interestedTreatmentPart, qInterestedTreatmentPart)
                .where(qCustomer.idName.eq(username)).fetchOne();

    }


    public void deleteOne(Long id, Long adminId) {

        Customer customer = findById(id);
        customer.setDeletedAt(LocalDateTime.now());

        Admin admin = adminRepositorySupport.findById(adminId);
        customer.setDeleteAdmin(admin);
    }


    public void restoreOne(Long id) {

        Customer customer = findById(id);
        if (customer.getCi() == null) {
            throw new UserRestoredException("CI 값이 없는 회원은 복원이 불가합니다. (CI 값이 없는 회원은 관리자에 의한 중지가 아닌, 탈퇴한 회원입니다. 아닐 경우, 시스템 관리자에게 문의하십시오.)");
        }

        customer.setDeletedAt(null);
        customer.setDeleteAdmin(null);

    }


    /*
        2. 사용자 생성
    * */
    public Customer createOne(Customer customer) {
        return customerRepository.save(customer);
    }


    public CustomerResDTO.Id updateOne(Long id, CustomerReqDTO.Update dto) {

        // 아래 두 가지 방법 중 한가지로 영속성 컨텍스트에 진입
        final Customer customer = customerRepository.findById(id).orElseThrow(() -> new ResourceNotFoundException("해당 고객을 찾을 수 없습니다. ID : '" + id));
        //entityManager.persist(customer);\

        // 이 시점 부터 영속성 컨텍스트에 진입
        customer.updateCustomer(dto);


        return new CustomerResDTO.Id(customer);
    }

    @Transactional(value = "commonTransactionManager", rollbackFor = Exception.class)
    public void createNewUserPoint(Long customerId) {

        Customer customer = findById(customerId);

        customer.setCurrentPoint(PointDetailStatus.고객의_신규_회원_가입_적립.getFixedPoint());

        PointDetailReqDTO.CreateOneWithCustomer createReqFromNewCustomer
                = new PointDetailReqDTO.CreateOneWithCustomer(PointDetailStatus.고객의_신규_회원_가입_적립.getValue(), PointDetailStatus.고객의_신규_회원_가입_적립.getFixedPoint());
        createReqFromNewCustomer.setPointSafe();
        pointDetailRepository.save(createReqFromNewCustomer.toEntity(customer));
    }

    @Transactional(value = "commonTransactionManager", rollbackFor = Exception.class)
    public Customer createKakaoCustomerWithPoints(SpringSecuritySocialOauthDTO.CreateCustomerRequest createCustomerRequest, SocialVendorOauthDTO.KaKaoUserInfo kaKaoUserInfo) {
        // 사용자 생성하기
        Customer justNowCreatedCustomer = customerRepository.save(createCustomerRequest.toEntityWithKakaoIdName(kaKaoUserInfo.getKakaoAccount().getEmail()));
        // [중요] 사용자 포인트 적립시켜 주기
        createNewUserPoint(justNowCreatedCustomer.getId());

        return justNowCreatedCustomer;
    }

    @Transactional(value = "commonTransactionManager", rollbackFor = Exception.class)
    public Customer createNaverCustomerWithPoints(SpringSecuritySocialOauthDTO.CreateCustomerRequest createCustomerRequest, SocialVendorOauthDTO.NaverUserInfo naverUserInfo) {
        // 사용자 생성하기
        Customer justNowCreatedCustomer = customerRepository.save(createCustomerRequest.toEntityWithKakaoIdName(naverUserInfo.getResponse().getEmail()));
        // [중요] 사용자 포인트 적립시켜 주기
        createNewUserPoint(justNowCreatedCustomer.getId());

        return justNowCreatedCustomer;
    }

    @Transactional(value = "commonTransactionManager", rollbackFor = Exception.class)
    public Customer createGoogleCustomerWithPoints(SpringSecuritySocialOauthDTO.CreateCustomerRequest createCustomerRequest, SocialVendorOauthDTO.GoogleUserInfo googleUserInfo) {
        // 사용자 생성하기
        Customer justNowCreatedCustomer = customerRepository.save(createCustomerRequest.toEntityWithGoogleIdName(googleUserInfo.getSub()));
        // [중요] 사용자 포인트 적립시켜 주기
        createNewUserPoint(justNowCreatedCustomer.getId());

        return justNowCreatedCustomer;
    }

    @Transactional(value = "commonTransactionManager", rollbackFor = Exception.class)
    public Customer createAppleCustomerWithPoints(SpringSecuritySocialOauthDTO.CreateAppleCustomerRequest createAppleCustomerRequest, AppleUserInfo appleUserInfo) {
        // 사용자 생성하기
        Customer justNowCreatedCustomer = customerRepository.save(createAppleCustomerRequest.toEntityWithAppleIdName(appleUserInfo.getSub()));
        // [중요] 사용자 포인트 적립시켜 주기
        createNewUserPoint(justNowCreatedCustomer.getId());

        return justNowCreatedCustomer;
    }

    @Transactional(value = "commonTransactionManager", rollbackFor = Exception.class)
    public Customer createNonSocialUser(CustomerReqDTO.Create create) {
        // 사용자 생성하기
        Customer justNowCreatedCustomer = customerRepository.save(create.toEntity());
        // [중요] 사용자 포인트 적립시켜 주기
        createNewUserPoint(justNowCreatedCustomer.getId());

        return justNowCreatedCustomer;
    }

    // https://velog.io/@jurlring/TransactionalreadOnly-true%EC%97%90%EC%84%9C-readOnly-true%EB%8A%94-%EB%AC%B4%EC%8A%A8-%EC%97%AD%ED%95%A0%EC%9D%B4%EA%B3%A0-%EA%BC%AD-%EC%8D%A8%EC%95%BC%ED%95%A0%EA%B9%8C
    @Transactional(value = "commonTransactionManager", readOnly = true)
    public List<StatisticsDTO.PeriodicOne> findMonthlyCustomerRegistrations(String dateRangeFilter) throws JsonProcessingException, ResourceNotFoundException {

        final QCustomer qCustomer = QCustomer.customer;

        // one to one
        final QInterestedTreatmentPart qInterestedTreatmentPart = QInterestedTreatmentPart.interestedTreatmentPart;

        StringTemplate formattedDate = stringTemplate(dbDialect.equals(SelectablePersistenceConst.MYSQL_8.getValue()) ? "DATE_FORMAT({0}, '%Y-%m')" : "FORMAT({0}, 'yyyy-MM')", qCustomer.createdAt);
        // alias 는 sorting 할 컬럼만 지정하면 됨
        JPQLQuery<StatisticsDTO.PeriodicOne> query = jpaQueryFactory
                .select(new QStatisticsDTO_PeriodicOne(formattedDate, qCustomer.count()))
                .from(qCustomer)
                .groupBy(stringTemplate(dbDialect.equals(SelectablePersistenceConst.MYSQL_8.getValue()) ? "DATE_FORMAT({0}, '%Y-%m')" : "FORMAT({0}, 'yyyy-MM')", qCustomer.createdAt));

        ObjectMapper objectMapper = new ObjectMapper();


        if (!CustomUtils.isEmpty(dateRangeFilter)) {
            DateRangeFilter deserializedDateRangeFilter = (DateRangeFilter) objectMapper.readValue(dateRangeFilter, DateRangeFilter.class);
            if (!CustomUtils.isEmpty(deserializedDateRangeFilter.getColumn())) {
                if ("createdAt".equals(deserializedDateRangeFilter.getColumn())) {

                    BooleanBuilder booleanBuilder = new BooleanBuilder();

                    if (!CustomUtils.isEmpty(deserializedDateRangeFilter.getStartDate())) {
                        Timestamp startTimestamp = Timestamp.valueOf(deserializedDateRangeFilter.getStartDate() + " 00:00:00");
                        booleanBuilder.and(qCustomer.createdAt.after(startTimestamp));
                    }
                    if (!CustomUtils.isEmpty(deserializedDateRangeFilter.getEndDate())) {
                        Timestamp endTimestamp = Timestamp.valueOf(deserializedDateRangeFilter.getEndDate() + " 23:59:59");
                        booleanBuilder.and(qCustomer.createdAt.before(endTimestamp));
                    }

                    query.where(booleanBuilder);

                } else {
                    throw new IllegalStateException("유효하지 않은 Date range 검색 대상입니다.");
                }
            }

        }
        return query.fetch();
    }

    public List<StatisticsDTO.NonPeriodicOne> findCustomersGender(String dateRangeFilter) throws JsonProcessingException {
        final QCustomer qCustomer = QCustomer.customer;

        JPQLQuery<StatisticsDTO.NonPeriodicOne> query = jpaQueryFactory
                .select(new QStatisticsDTO_NonPeriodicOne(
                        new CaseBuilder()
                                .when(qCustomer.sex.eq("F")).then("여성")
                                .when(qCustomer.sex.eq("M")).then("남성")
                                .otherwise(""),
                        qCustomer.sex.count())
                )
                .from(qCustomer)
                .where(qCustomer.sex.isNotNull());

        ObjectMapper objectMapper = new ObjectMapper();
        if (!CustomUtils.isEmpty(dateRangeFilter)) {
            DateRangeFilter deserializedDateRangeFilter = (DateRangeFilter) objectMapper.readValue(dateRangeFilter, DateRangeFilter.class);
            if (!CustomUtils.isEmpty(deserializedDateRangeFilter.getColumn())) {
                if ("createdAt".equals(deserializedDateRangeFilter.getColumn())) {

                    BooleanBuilder booleanBuilder = new BooleanBuilder();

                    if (!CustomUtils.isEmpty(deserializedDateRangeFilter.getStartDate())) {
                        Timestamp startTimestamp = Timestamp.valueOf(deserializedDateRangeFilter.getStartDate() + " 00:00:00");
                        booleanBuilder.and(qCustomer.createdAt.after(startTimestamp));
                    }
                    if (!CustomUtils.isEmpty(deserializedDateRangeFilter.getEndDate())) {
                        Timestamp endTimestamp = Timestamp.valueOf(deserializedDateRangeFilter.getEndDate() + " 23:59:59");
                        booleanBuilder.and(qCustomer.createdAt.before(endTimestamp));
                    }
                    query.where(booleanBuilder);
                } else {
                    throw new IllegalStateException("유효하지 않은 Date range 검색 대상입니다.");
                }
            }

        }
        return query.groupBy(qCustomer.sex).fetch();
    }


    public StatisticsDTO.PrevCurrentDiff getCustomerRegisteredDiff(TimePeriod timePeriod) {

        TimePeriodUtils.TimestampRange timestampRange = TimePeriodUtils.calculateTimestampRange(timePeriod);

        final QCustomer qCustomer = QCustomer.customer;

        Long prevSumCount = jpaQueryFactory
                .select(qCustomer.id.count())
                .from(qCustomer)
                .where(qCustomer.createdAt.before(timestampRange.getStandardDateTime()))
                .fetchOne();

        Long currentCount = jpaQueryFactory
                .select(qCustomer.id.count())
                .from(qCustomer)
                .where(qCustomer.createdAt.between(timestampRange.getStandardDateTime(), timestampRange.getCurrentDateTime()))
                .fetchOne();

        return new StatisticsDTO.PrevCurrentDiff(prevSumCount, currentCount);
    }

    public StatisticsDTO.PrevCurrentDiff getCustomerDeletedDiff(TimePeriod timePeriod) {

        TimePeriodUtils.TimestampRange timestampRange = TimePeriodUtils.calculateTimestampRange(timePeriod);

        final QCustomer qCustomer = QCustomer.customer;

        Long prevSumCount = jpaQueryFactory
                .select(qCustomer.id.count())
                .from(qCustomer)
                .where(
                        qCustomer.deletedAt.before(timestampRange.getStandardDateTime().toLocalDateTime()),
                        qCustomer.deletedCi.isNotNull()
                )
                .fetchOne();

        Long currentCount = jpaQueryFactory
                .select(qCustomer.id.count())
                .from(qCustomer)
                .where(
                        qCustomer.deletedAt.between(timestampRange.getStandardDateTime().toLocalDateTime(), timestampRange.getCurrentDateTime().toLocalDateTime()),
                        qCustomer.deletedCi.isNotNull()
                )
                .fetchOne();

        return new StatisticsDTO.PrevCurrentDiff(prevSumCount, currentCount);
    }

    public CustomerResDTO.SensitiveInfoAgreeWithPushAgrees findOneWithPushAgreesById(Long customerId) {
        final QCustomer qCustomer = QCustomer.customer;
        final QPushAgree qPushAgree = QPushAgree.pushAgree1;

        JPQLQuery<CustomerResDTO.SensitiveInfoAgreeWithPushAgrees> query = jpaQueryFactory
                .select(new QCustomerResDTO_SensitiveInfoAgreeWithPushAgrees(
                        qCustomer.id, qCustomer.sensitiveInfo, qCustomer.createdAt, qCustomer.sensitiveInfoUpdatedAt, qPushAgree.pushAgree, qPushAgree.nightPushAgree, qPushAgree.createdAt, qPushAgree.updatedAt))
                .from(qCustomer)
                .where(qCustomer.id.eq(customerId))
                .leftJoin(qPushAgree).on(qPushAgree.customer.id.eq(qCustomer.id));

        return query.fetchOne();
    }

    public CustomerResDTO.Id updateMeWithPushAgrees(Customer customer, CustomerReqDTO.UpdateSensitiveInfoWithPushAgrees dto) {
        customer.updateSensitiveInfo(dto);
        return new CustomerResDTO.Id(customer);
    }

    public StatisticsDTO.AgeRangeCaseAndCount findCustomersAgeRange(String dateRangeFilter) throws JsonProcessingException {
        final QCustomer qCustomer = QCustomer.customer;
        LocalDate now = LocalDate.now();

        JPQLQuery<StatisticsDTO.AgeRangeCaseAndCount> query = jpaQueryFactory
                .select(new QStatisticsDTO_AgeRangeCaseAndCount(
                                new CaseBuilder()
                                        .when(qCustomer.birthday.between(
                                                LocalDate.of(now.minusYears(19).getYear(), 1, 1), LocalDate.of(now.getYear(), 12, 31)
                                        )).then(1).otherwise(0).castToNum(Long.class).sum(),
                                new CaseBuilder()
                                        .when(qCustomer.birthday.between(
                                                LocalDate.of(now.minusYears(29).getYear(), 1, 1), LocalDate.of(now.minusYears(20).getYear(), 12, 31)
                                        )).then(1).otherwise(0).castToNum(Long.class).sum(),
                                new CaseBuilder()
                                        .when(qCustomer.birthday.between(
                                                LocalDate.of(now.minusYears(39).getYear(), 1, 1), LocalDate.of(now.minusYears(30).getYear(), 12, 31)
                                        )).then(1).otherwise(0).castToNum(Long.class).sum(),
                                new CaseBuilder()
                                        .when(qCustomer.birthday.between(
                                                LocalDate.of(now.minusYears(49).getYear(), 1, 1), LocalDate.of(now.minusYears(40).getYear(), 12, 31)
                                        )).then(1).otherwise(0).castToNum(Long.class).sum(),
                                new CaseBuilder()
                                        .when(qCustomer.birthday.between(
                                                LocalDate.of(now.minusYears(59).getYear(), 1, 1), LocalDate.of(now.minusYears(50).getYear(), 12, 31)
                                        )).then(1).otherwise(0).castToNum(Long.class).sum(),
                                new CaseBuilder()
                                        .when(qCustomer.birthday.loe(
                                                LocalDate.of(now.minusYears(60).getYear(), 12, 31))
                                        ).then(1).otherwise(0).castToNum(Long.class).sum()
                        )
                )
                .from(qCustomer)
                .where(qCustomer.birthday.isNotNull());

        ObjectMapper objectMapper = new ObjectMapper();
        if (!CustomUtils.isEmpty(dateRangeFilter)) {
            DateRangeFilter deserializedDateRangeFilter = (DateRangeFilter) objectMapper.readValue(dateRangeFilter, DateRangeFilter.class);
            if (!CustomUtils.isEmpty(deserializedDateRangeFilter.getColumn())) {
                if ("createdAt".equals(deserializedDateRangeFilter.getColumn())) {

                    BooleanBuilder booleanBuilder = new BooleanBuilder();

                    if (!CustomUtils.isEmpty(deserializedDateRangeFilter.getStartDate())) {
                        Timestamp startTimestamp = Timestamp.valueOf(deserializedDateRangeFilter.getStartDate() + " 00:00:00");
                        booleanBuilder.and(qCustomer.createdAt.after(startTimestamp));
                    }
                    if (!CustomUtils.isEmpty(deserializedDateRangeFilter.getEndDate())) {
                        Timestamp endTimestamp = Timestamp.valueOf(deserializedDateRangeFilter.getEndDate() + " 23:59:59");
                        booleanBuilder.and(qCustomer.createdAt.before(endTimestamp));
                    }

                    query.where(booleanBuilder);

                } else {
                    throw new IllegalStateException("유효하지 않은 Date range 검색 대상입니다.");
                }
            }
        }
        return query.fetchOne();
    }

    public StatisticsDTO.JoinTypeCaseAndCount findCustomersJoinType(String dateRangeFilter) throws JsonProcessingException {
        final QCustomer qCustomer = QCustomer.customer;

        JPQLQuery<StatisticsDTO.JoinTypeCaseAndCount> query = jpaQueryFactory
                .select(new QStatisticsDTO_JoinTypeCaseAndCount(
                                new CaseBuilder()
                                        .when(qCustomer.password.isNotNull()).then(1).otherwise(0).castToNum(Long.class).sum(),
                                new CaseBuilder()
                                        .when(qCustomer.kakaoIdName.isNotNull()).then(1).otherwise(0).castToNum(Long.class).sum(),
                                new CaseBuilder()
                                        .when(qCustomer.naverIdName.isNotNull()).then(1).otherwise(0).castToNum(Long.class).sum(),
                                new CaseBuilder()
                                        .when(qCustomer.appleIdName.isNotNull()).then(1).otherwise(0).castToNum(Long.class).sum(),
                                new CaseBuilder()
                                        .when(qCustomer.googleIdName.isNotNull()).then(1).otherwise(0).castToNum(Long.class).sum()
                        )
                )
                .from(qCustomer);

        ObjectMapper objectMapper = new ObjectMapper();
        if (!CustomUtils.isEmpty(dateRangeFilter)) {
            DateRangeFilter deserializedDateRangeFilter = (DateRangeFilter) objectMapper.readValue(dateRangeFilter, DateRangeFilter.class);
            if (!CustomUtils.isEmpty(deserializedDateRangeFilter.getColumn())) {
                if ("createdAt".equals(deserializedDateRangeFilter.getColumn())) {

                    BooleanBuilder booleanBuilder = new BooleanBuilder();

                    if (!CustomUtils.isEmpty(deserializedDateRangeFilter.getStartDate())) {
                        Timestamp startTimestamp = Timestamp.valueOf(deserializedDateRangeFilter.getStartDate() + " 00:00:00");
                        booleanBuilder.and(qCustomer.createdAt.after(startTimestamp));
                    }
                    if (!CustomUtils.isEmpty(deserializedDateRangeFilter.getEndDate())) {
                        Timestamp endTimestamp = Timestamp.valueOf(deserializedDateRangeFilter.getEndDate() + " 23:59:59");
                        booleanBuilder.and(qCustomer.createdAt.before(endTimestamp));
                    }

                    query.where(booleanBuilder);

                } else {
                    throw new IllegalStateException("유효하지 않은 Date range 검색 대상입니다.");
                }
            }
        }
        return query.fetchOne();
    }

    public CustomerResDTO.Id updateMePasswordAndEmail(Customer customer, CustomerReqDTO.UpdatePasswordAndEmail dto) {
        customer.updatePasswordAndEmail(dto);
        return new CustomerResDTO.Id(customer);
    }
}
