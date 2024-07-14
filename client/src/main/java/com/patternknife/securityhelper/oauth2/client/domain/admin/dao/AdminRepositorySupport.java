package com.patternknife.securityhelper.oauth2.client.domain.admin.dao;

import com.patternknife.securityhelper.oauth2.client.config.database.CommonQuerydslRepositorySupport;
import com.patternknife.securityhelper.oauth2.client.config.response.error.exception.data.ResourceNotFoundException;
import com.patternknife.securityhelper.oauth2.client.domain.admin.entity.Admin;
import com.querydsl.jpa.impl.JPAQueryFactory;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Repository;

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
