package com.patternknife.securityhelper.oauth2.domain.admin.dao;

import com.patternknife.securityhelper.oauth2.config.database.CommonQuerydslRepositorySupport;
import com.patternknife.securityhelper.oauth2.config.response.error.exception.data.ResourceNotFoundException;
import com.patternknife.securityhelper.oauth2.domain.admin.entity.Admin;
import com.querydsl.jpa.impl.JPAQueryFactory;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Repository;

/*
*
*   QueryDsl 을 써야하는 경우 = 다른 엔터티들 Join, Group by, having... + 동적 where
*
*   Repository 에는 Repository 가 다른 엔터티 종류는 못옴
* */
@Repository
public class AdminRepositorySupport extends CommonQuerydslRepositorySupport {

    private final JPAQueryFactory jpaQueryFactory;

    private final AdminRepository adminRepository;

    private EntityManager entityManager;

    public AdminRepositorySupport(AdminRepository adminRepository, @Qualifier("authJpaQueryFactory") JPAQueryFactory jpaQueryFactory) {

        super(Admin.class);
        this.adminRepository = adminRepository;
        this.jpaQueryFactory = jpaQueryFactory;
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



}
