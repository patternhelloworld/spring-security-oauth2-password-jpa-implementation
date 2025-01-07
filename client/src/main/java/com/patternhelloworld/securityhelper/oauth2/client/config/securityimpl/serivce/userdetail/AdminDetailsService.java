package com.patternhelloworld.securityhelper.oauth2.client.config.securityimpl.serivce.userdetail;


import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.core.EasyPlusUserInfo;
import com.patternhelloworld.securityhelper.oauth2.client.config.securityimpl.guard.CustomizedUserInfo;

import com.patternhelloworld.securityhelper.oauth2.client.domain.admin.dao.AdminRepository;
import com.patternhelloworld.securityhelper.oauth2.client.domain.admin.entity.Admin;

import com.patternhelloworld.securityhelper.oauth2.client.domain.admin.entity.QAdmin;
import com.patternhelloworld.securityhelper.oauth2.client.domain.admin.entity.QAdminRole;
import com.patternhelloworld.securityhelper.oauth2.client.domain.role.entity.QRole;
import com.querydsl.jpa.impl.JPAQueryFactory;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.dao.EasyPlusClientRepository;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.jpa.repository.support.QuerydslRepositorySupport;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collection;


@Service
public class AdminDetailsService extends QuerydslRepositorySupport implements UserDetailsService {

    private final JPAQueryFactory jpaQueryFactory;

    private final AdminRepository adminRepository;
    private final EasyPlusClientRepository easyPlusClientRepository;

    private EntityManager entityManager;

    public AdminDetailsService(AdminRepository adminRepository,
                               @Qualifier("authJpaQueryFactory") JPAQueryFactory jpaQueryFactory, EasyPlusClientRepository easyPlusClientRepository) {
        super(Admin.class);
        this.adminRepository = adminRepository;
        this.jpaQueryFactory = jpaQueryFactory;
        this.easyPlusClientRepository = easyPlusClientRepository;
    }

    @Override
    @PersistenceContext(unitName = "commonEntityManager")
    public void setEntityManager(EntityManager entityManager) {
        super.setEntityManager(entityManager);
        this.entityManager = entityManager;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        Admin admin = adminRepository.findByIdName(username).orElseThrow(() -> new UsernameNotFoundException("Admin (ID : \"" + username + "\") NOT found."));
        if(admin.getDeletedAt() != null){
            throw new DisabledException(admin.getIdName() + "'s account is currently disabled.");
        }
/*        GoogleOtpResolver adminBO = new GoogleOtpResolver();
        GoogleAuthenticatorKey secretKey = adminBO.generateOtpSecretKey();
        String qrUrl = adminBO.generateOtpSecretQrCodeUrl(admin.getIdName(), secretKey);*/

        return buildAdminForAuthentication(admin, getAuthorities(admin.getId()));

    }

    public Admin findByIdWithOrganizationRole(Long id) {

        final QAdmin qAdmin = QAdmin.admin;
        final QAdminRole qAdminRole = QAdminRole.adminRole;
        final QRole qRole = QRole.role;

        return jpaQueryFactory.selectFrom(qAdmin)
                .leftJoin(qAdmin.adminRoles, qAdminRole).fetchJoin().leftJoin(qAdminRole.role, qRole).fetchJoin()
                .where(qAdmin.id.eq(id)).fetchOne();

    }


    private EasyPlusUserInfo<CustomizedUserInfo> buildAdminForAuthentication(Admin admin, Collection<? extends GrantedAuthority> authorities) {

        String username = admin.getIdName();
        String password = admin.getPassword().getValue();

        boolean enabled = true;
        boolean accountNonExpired = true;
        boolean credentialsNonExpired = true;
        boolean accountNonLocked = true;

        EasyPlusUserInfo<CustomizedUserInfo> authUser = new EasyPlusUserInfo<>(username, password, enabled, accountNonExpired, credentialsNonExpired,
                accountNonLocked, authorities);

        authUser.setCustomizedUserInfo(new CustomizedUserInfo(admin));

        return authUser;
    }

    private Collection<? extends GrantedAuthority> getAuthorities(Long adminId) {

        Admin admin = findByIdWithOrganizationRole(adminId);

        // Check if getCustomerRoles() returns null
        if (admin.getAdminRoles() == null) {
            // Return an empty authority collection if customer roles are null
            return new ArrayList<GrantedAuthority>();
        }

        String[] adminRoles = admin.getAdminRoles().stream().map((adminRole) -> adminRole.getRole().getName()).toArray(String[]::new);
        Collection<GrantedAuthority> authorities = AuthorityUtils.createAuthorityList(adminRoles);
        return authorities;
    }


}