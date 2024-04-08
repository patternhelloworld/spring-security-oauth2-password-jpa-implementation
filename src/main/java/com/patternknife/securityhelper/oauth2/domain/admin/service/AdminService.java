package com.patternknife.securityhelper.oauth2.domain.admin.service;


import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.patternknife.securityhelper.oauth2.config.database.CommonQuerydslRepositorySupport;
import com.patternknife.securityhelper.oauth2.config.database.SelectablePersistenceConst;
import com.patternknife.securityhelper.oauth2.config.response.error.exception.data.ResourceNotFoundException;
import com.patternknife.securityhelper.oauth2.config.security.principal.AccessTokenUserInfo;
import com.patternknife.securityhelper.oauth2.domain.admin.dao.AdminRepository;
import com.patternknife.securityhelper.oauth2.domain.admin.dao.AdminRoleRepository;
import com.patternknife.securityhelper.oauth2.domain.admin.dto.AdminDTO;
import com.patternknife.securityhelper.oauth2.domain.admin.dto.AdminSearchFilter;
import com.patternknife.securityhelper.oauth2.domain.admin.dto.QAdminDTO_OneWithRoleIdsRes;
import com.patternknife.securityhelper.oauth2.domain.admin.entity.*;
import com.patternknife.securityhelper.oauth2.domain.common.dto.DateRangeFilter;
import com.patternknife.securityhelper.oauth2.domain.common.dto.SorterValueFilter;
import com.patternknife.securityhelper.oauth2.domain.role.dao.RoleRepository;
import com.patternknife.securityhelper.oauth2.domain.role.entity.QRole;
import com.patternknife.securityhelper.oauth2.domain.role.entity.Role;
import com.patternknife.securityhelper.oauth2.util.CommonConstant;
import com.patternknife.securityhelper.oauth2.util.CustomUtils;
import com.patternknife.securityhelper.oauth2.util.PaginationUtil;
import com.querydsl.core.BooleanBuilder;
import com.querydsl.core.types.dsl.Expressions;
import com.querydsl.jpa.JPQLQuery;
import com.querydsl.jpa.impl.JPAQueryFactory;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Page;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.sql.Timestamp;
import java.util.Set;


@Service
public class AdminService extends CommonQuerydslRepositorySupport {

    private final JPAQueryFactory jpaQueryFactory;

    private final AdminRepository adminRepository;
    private final RoleRepository roleRepository;
    private final AdminRoleRepository adminRoleRepository;

    private EntityManager entityManager;

    private final String dbDialect;

    public AdminService(AdminRepository adminRepository, RoleRepository roleRepository,
                       AdminRoleRepository adminRoleRepository,
                       @Qualifier("authJpaQueryFactory") JPAQueryFactory jpaQueryFactory,
                        @Value("${spring.jpa.properties.hibernate.dialect}") String dbDialect) {
        super(Admin.class);
        this.adminRepository = adminRepository;
        this.roleRepository = roleRepository;
        this.adminRoleRepository = adminRoleRepository;
        this.jpaQueryFactory = jpaQueryFactory;
        this.dbDialect  = dbDialect;
    }

    @Override
    @PersistenceContext(unitName = "commonEntityManager")
    public void setEntityManager(EntityManager entityManager) {
        super.setEntityManager(entityManager);
        this.entityManager = entityManager;
    }


    public Admin findById(Long id) throws ResourceNotFoundException {
        return adminRepository.findById(id).orElseThrow(() -> new ResourceNotFoundException("findById - Admin not found for this id :: " + id));
    }
    public Admin findByIdWithOrganizationRole(Long id) {

        final QAdmin qAdmin = QAdmin.admin;
        final QAdminRole qAdminRole = QAdminRole.adminRole;
        final QRole qRole = QRole.role;

        return jpaQueryFactory.selectFrom(qAdmin)
                .leftJoin(qAdmin.adminRoles, qAdminRole).fetchJoin().leftJoin(qAdminRole.role, qRole).fetchJoin()
                .where(qAdmin.id.eq(id)).fetchOne();

    }
    public Admin findByIdNameWithOrganizationRole(String idName) {

        final QAdmin qAdmin = QAdmin.admin;
        final QAdminRole qAdminRole = QAdminRole.adminRole;
        final QRole qRole = QRole.role;

        return jpaQueryFactory.selectFrom(qAdmin)
                .leftJoin(qAdmin.adminRoles, qAdminRole).fetchJoin().leftJoin(qAdminRole.role, qRole).fetchJoin()
                .where(qAdmin.idName.eq(idName)).fetchOne();

    }
    public Boolean checkSuperAdminFromAccessTokeAdminInfo(AccessTokenUserInfo accessTokenUserInfo) throws ResourceNotFoundException {

        Boolean superAdmin = false;

        Set<String> adminRoles = AuthorityUtils.authorityListToSet(accessTokenUserInfo.getAuthorities());

        if (adminRoles != null && adminRoles.size() > 0) {
            for (String role : adminRoles) {
                if (role.equals(CommonConstant.SUPER_ADMIN_ROLE_NAME)) {
                    superAdmin = true;
                }
            }
        }

        return superAdmin;
    }

    public AdminDTO.OneWithRoleIdsRes findAdminWithRoleIdsByAdminId(Long adminId){

        final QAdmin qAdmin = QAdmin.admin;

        // one to many
        final QAdminRole qAdminRole = QAdminRole.adminRole;
        final QRole qRole = QRole.role;


        JPQLQuery<AdminDTO.OneWithRoleIdsRes> query = jpaQueryFactory
                .select(new QAdminDTO_OneWithRoleIdsRes(qAdmin.id, qAdmin.idName, qAdmin.description,
                        dbDialect.equals(SelectablePersistenceConst.MYSQL_8.getValue()) ?
                                Expressions.stringTemplate("group_concat({0})", qRole.id).as("commaSplitRoleIds") :
                                dbDialect.equals(SelectablePersistenceConst.MSSQL.getValue()) ?
                                        Expressions.stringTemplate("STRING_AGG({0}, ',')", qRole.id).as("commaSplitRoleIds") : null,
                        qAdmin.createdAt, qAdmin.updatedAt))
                .from(qAdmin)
                .leftJoin(qAdmin.adminRoles, qAdminRole)
                .leftJoin(qAdminRole.role, qRole)
                .groupBy(qAdmin.id, qAdmin.idName, qAdmin.description, qAdmin.createdAt, qAdmin.updatedAt)
                .where(qAdmin.id.eq(adminId));

        return query.fetchOne();

    }


    // https://velog.io/@jurlring/TransactionalreadOnly-true%EC%97%90%EC%84%9C-readOnly-true%EB%8A%94-%EB%AC%B4%EC%8A%A8-%EC%97%AD%ED%95%A0%EC%9D%B4%EA%B3%A0-%EA%BC%AD-%EC%8D%A8%EC%95%BC%ED%95%A0%EA%B9%8C
    @Transactional(value = "commonTransactionManager", readOnly = true)
    public Page<AdminDTO.OneWithRoleIdsRes> findAdminsByPageRequest(Boolean skipPagination,
                                                                    Integer pageNum,
                                                                    Integer pageSize,
                                                                    String adminSearchFilter,
                                                                    String sorterValueFilter,
                                                                    String dateRangeFilter,
                                                                    AccessTokenUserInfo accessTokenUserInfo) throws JsonProcessingException, ResourceNotFoundException {

        final QAdmin qAdmin = QAdmin.admin;


        /*        dbDialect.equals(SelectablePersistenceConst.MYSQL_8.getValue()) ?
                Expressions.stringTemplate("group_concat(CONCAT('{\"label\":\"', {0}, '\", \"value\":', {1}, '}'))",
                        qRole.name, qRole.id).as("commaSplitRoleNames"):
                dbDialect.equals(SelectablePersistenceConst.MSSQL.getValue()) ?
                        Expressions.stringTemplate("STRING_AGG(CONCAT('{\"label\":\"', {0}, '\", \"value\":', {1}, '}'), ',')",
                                qRole.name, qRole.id).as("commaSplitRoleNames") : null,*/

        // one to many
        final QAdminRole qAdminRole = QAdminRole.adminRole;
        final QRole qRole = QRole.role;


        JPQLQuery<AdminDTO.OneWithRoleIdsRes> query = jpaQueryFactory
                .select(new QAdminDTO_OneWithRoleIdsRes(qAdmin.id, qAdmin.idName, qAdmin.description,
                        dbDialect.equals(SelectablePersistenceConst.MYSQL_8.getValue()) ?
                                Expressions.stringTemplate("group_concat({0})", qRole.id).as("commaSplitRoleIds") :
                       dbDialect.equals(SelectablePersistenceConst.MSSQL.getValue()) ?
                                Expressions.stringTemplate("STRING_AGG({0}, ',')", qRole.id).as("commaSplitRoleIds") : null,
                        qAdmin.createdAt, qAdmin.updatedAt))
                .from(qAdmin)
                // OneToMany
                .leftJoin(qAdmin.adminRoles, qAdminRole)
                .leftJoin(qAdminRole.role, qRole);

        JPQLQuery<Long> countQuery = jpaQueryFactory
                .select(qAdmin.id)
                .from(qAdmin)
                // OneToMany
                .leftJoin(qAdmin.adminRoles, qAdminRole)
                .leftJoin(qAdminRole.role, qRole);


        query.groupBy(qAdmin.id, qAdmin.idName, qAdmin.description, qAdmin.createdAt, qAdmin.updatedAt);
        countQuery.groupBy(qAdmin.id);

        ObjectMapper objectMapper = new ObjectMapper();

        if(!CustomUtils.isEmpty(adminSearchFilter)) {
            AdminSearchFilter deserializedAdminSearchFilter = (AdminSearchFilter) objectMapper.readValue(adminSearchFilter, AdminSearchFilter.class);

            if (!CustomUtils.isEmpty(deserializedAdminSearchFilter.getIdName())) {
                query.where(qAdmin.idName.likeIgnoreCase("%" + deserializedAdminSearchFilter.getIdName() + "%"));
                countQuery.where(qAdmin.idName.likeIgnoreCase("%" + deserializedAdminSearchFilter.getIdName() + "%"));
            }

        }

        if(!CustomUtils.isEmpty(dateRangeFilter)) {
            DateRangeFilter deserializedDateRangeFilter = (DateRangeFilter) objectMapper.readValue(dateRangeFilter, DateRangeFilter.class);
            if (!CustomUtils.isEmpty(deserializedDateRangeFilter.getColumn())) {
                if ("createdAt".equals(deserializedDateRangeFilter.getColumn())) {

                    BooleanBuilder booleanBuilder = new BooleanBuilder();

                    if (!CustomUtils.isEmpty(deserializedDateRangeFilter.getStartDate())) {
                        Timestamp startTimestamp = Timestamp.valueOf(deserializedDateRangeFilter.getStartDate() + " 00:00:00");
                        booleanBuilder.and(qAdmin.createdAt.after(startTimestamp));
                    }
                    if (!CustomUtils.isEmpty(deserializedDateRangeFilter.getEndDate())) {
                        Timestamp endTimestamp = Timestamp.valueOf(deserializedDateRangeFilter.getEndDate() + " 23:59:59");
                        booleanBuilder.and(qAdmin.createdAt.before(endTimestamp));
                    }

                    query.where(booleanBuilder);
                    countQuery.where(booleanBuilder);

                }else if ("updatedAt".equals(deserializedDateRangeFilter.getColumn())) {

                    BooleanBuilder booleanBuilder = new BooleanBuilder();

                    if (!CustomUtils.isEmpty(deserializedDateRangeFilter.getStartDate())) {
                        Timestamp startTimestamp = Timestamp.valueOf(deserializedDateRangeFilter.getStartDate() + " 00:00:00");
                        booleanBuilder.and(qAdmin.updatedAt.after(startTimestamp));
                    }
                    if (!CustomUtils.isEmpty(deserializedDateRangeFilter.getEndDate())) {
                        Timestamp endTimestamp = Timestamp.valueOf(deserializedDateRangeFilter.getEndDate() + " 23:59:59");
                        booleanBuilder.and(qAdmin.updatedAt.before(endTimestamp));
                    }

                    query.where(booleanBuilder);
                    countQuery.where(booleanBuilder);

                }  else {
                    throw new IllegalStateException("NOT a valid date range");
                }
            }

        }


        if(!CustomUtils.isEmpty(sorterValueFilter)) {
            SorterValueFilter deserializedSorterValueFilter = (SorterValueFilter) objectMapper.readValue(sorterValueFilter, SorterValueFilter.class);

            String sortedColumn = deserializedSorterValueFilter.getColumn();

            switch (sortedColumn) {
                case "id":
                    query.orderBy(deserializedSorterValueFilter.getAsc() ? qAdmin.id.asc() : qAdmin.id.desc());
                    break;
                case "idName":
                    query.orderBy(deserializedSorterValueFilter.getAsc() ? qAdmin.idName.asc() : qAdmin.idName.desc());
                    break;
                case "description":
                    query.orderBy(deserializedSorterValueFilter.getAsc() ? qAdmin.description.asc() : qAdmin.description.desc());
                    break;
                case "createdAt":
                    query.orderBy(deserializedSorterValueFilter.getAsc() ? qAdmin.createdAt.asc() : qAdmin.createdAt.desc());
                    break;
                case "updatedAt":
                    query.orderBy(deserializedSorterValueFilter.getAsc() ? qAdmin.updatedAt.asc() : qAdmin.updatedAt.desc());
                    break;
                default:
                    throw new IllegalArgumentException("Not a valid sort column : " + sortedColumn);
            }
        }


        // Pagination
        PaginationUtil paginationUtil = new PaginationUtil(getQuerydsl());
        return paginationUtil.applyPagination(query, pageNum, pageSize, skipPagination, countQuery.fetchCount());

    }


    public Admin create(AdminDTO.CreateReq dto){
        return adminRepository.save(dto.toEntity());
    }

    @Transactional(value = "commonTransactionManager", rollbackFor=Exception.class)
    public AdminDTO.UpdateRes update(Long id, AdminDTO.UpdateReq dto) {


       Admin admin = adminRepository.findById(id).orElseThrow(() -> new ResourceNotFoundException("Couldn't find the Admin (ID : '" + id + "')"));
       admin.setIdName(dto.getIdName());

        if(dto.getPassword() != null){
            admin.setPassword(Password.builder().value(dto.getPassword()).build());
        }

       adminRoleRepository.deleteByAdmin(admin);

        for (Integer roleId : dto.getCommaSplitRoleIds()) {
            Role role = roleRepository.findById(roleId.longValue())
                    .orElseThrow(() -> new ResourceNotFoundException("Authority is NOT confirmed (ID " + roleId + ")"));
            AdminRole adminRole = new AdminRole();
            adminRole.setAdmin(admin);
            adminRole.setRole(role);

            adminRoleRepository.save(adminRole);
        }

        return new AdminDTO.UpdateRes(admin);
    }

}