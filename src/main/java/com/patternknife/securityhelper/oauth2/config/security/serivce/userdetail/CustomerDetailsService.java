package com.patternknife.securityhelper.oauth2.config.security.serivce.userdetail;


import com.patternknife.securityhelper.oauth2.config.response.error.exception.auth.UserDeletedException;
import com.patternknife.securityhelper.oauth2.config.response.error.exception.data.ResourceNotFoundException;
import com.patternknife.securityhelper.oauth2.config.security.dao.OauthClientDetailRepository;
import com.patternknife.securityhelper.oauth2.config.security.principal.AccessTokenUserInfo;
import com.patternknife.securityhelper.oauth2.config.security.principal.AdditionalAccessTokenUserInfo;
import com.patternknife.securityhelper.oauth2.domain.customer.dao.CustomerRepository;
import com.patternknife.securityhelper.oauth2.domain.customer.entity.Customer;
import com.patternknife.securityhelper.oauth2.domain.customer.entity.QCustomer;
import com.patternknife.securityhelper.oauth2.domain.customer.entity.QCustomerRole;
import com.patternknife.securityhelper.oauth2.domain.role.entity.QRole;
import com.querydsl.jpa.impl.JPAQueryFactory;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.jpa.repository.support.QuerydslRepositorySupport;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collection;


@Service
public class CustomerDetailsService extends QuerydslRepositorySupport implements UserDetailsService {

    private final JPAQueryFactory jpaQueryFactory;

    private final CustomerRepository customerRepository;
    private final OauthClientDetailRepository oauthClientDetailRepository;

    private EntityManager entityManager;

    public CustomerDetailsService (CustomerRepository customerRepository, OauthClientDetailRepository oauthClientDetailRepository,
                       @Qualifier("authJpaQueryFactory") JPAQueryFactory jpaQueryFactory) {
        super(Customer.class);
        this.customerRepository = customerRepository;
        this.oauthClientDetailRepository = oauthClientDetailRepository;
        this.jpaQueryFactory = jpaQueryFactory;
    }

    @Override
    @PersistenceContext(unitName = "commonEntityManager")
    public void setEntityManager(EntityManager entityManager) {
        super.setEntityManager(entityManager);
        this.entityManager = entityManager;
    }

    @Override
    public UserDetails loadUserByUsername(String username)  {

        Customer customer = customerRepository.findByIdName(username).orElseThrow(() -> new ResourceNotFoundException("사용자 (ID : \"" + username + "\") 을 찾을 수 없습니다."));
        if(customer.getDeletedAt() != null){
            if(customer.getDeleteAdminId() == null) {
                if (customer.getOneWeekAfterDeletedAsString() != null) {
                    throw new UserDeletedException("탈퇴한 계정으로써, " + customer.getOneWeekAfterDeletedAsString() + " 까지 재가입이 불가합니다.");
                } else {
                    throw new UserDeletedException("탈퇴한 계정입니다.");
                }
            }else{
                throw new UserDeletedException("관리자에 의해 정지 된 계정입니다.");
            }
        }

        return buildCustomerForAuthentication(customer, getAuthorities(customer.getId()));

    }

    public Customer findByIdWithOrganizationRole(Long id) {

        final QCustomer qCustomer = QCustomer.customer;
        final QCustomerRole qCustomerRole = QCustomerRole.customerRole;
        final QRole qRole = QRole.role;

        return jpaQueryFactory.selectFrom(qCustomer)
                .leftJoin(qCustomer.customerRoles, qCustomerRole).fetchJoin().leftJoin(qCustomerRole.role, qRole).fetchJoin()
                .where(qCustomer.id.eq(id)).fetchOne();

    }


    private AccessTokenUserInfo buildCustomerForAuthentication(Customer customer, Collection<? extends GrantedAuthority> authorities) {
        String customername = customer.getIdName();
        String password = customer.getPassword() != null ? customer.getPassword().getValue() : "";
        boolean enabled = true;
        boolean accountNonExpired = true;
        boolean credentialsNonExpired = true;
        boolean accountNonLocked = true;

        AccessTokenUserInfo authCustomer = new AccessTokenUserInfo(customername, password, enabled, accountNonExpired, credentialsNonExpired,
                accountNonLocked, authorities);

        authCustomer.setAdditionalAccessTokenUserInfo(new AdditionalAccessTokenUserInfo(customer));

        return authCustomer;
    }

    private Collection<? extends GrantedAuthority> getAuthorities(Long customerId) {

        Customer customer = findByIdWithOrganizationRole(customerId);

        // Check if getCustomerRoles() returns null
        if (customer.getCustomerRoles() == null) {
            // Return an empty authority collection if customer roles are null
            return new ArrayList<GrantedAuthority>();
        }

        String[] customerRoles = customer.getCustomerRoles().stream().map((customerRole) -> customerRole.getRole().getName()).toArray(String[]::new);
        Collection<GrantedAuthority> authorities = AuthorityUtils.createAuthorityList(customerRoles);
        return authorities;
    }


}