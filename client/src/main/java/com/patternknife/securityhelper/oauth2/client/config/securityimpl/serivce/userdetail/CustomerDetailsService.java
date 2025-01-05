package com.patternknife.securityhelper.oauth2.client.config.securityimpl.serivce.userdetail;


import io.github.patternknife.securityhelper.oauth2.api.config.security.core.KnifeUserInfo;
import com.patternknife.securityhelper.oauth2.client.config.securityimpl.guard.CustomizedUserInfo;
import com.patternknife.securityhelper.oauth2.client.config.response.error.exception.auth.UserDeletedException;

import com.patternknife.securityhelper.oauth2.client.domain.customer.dao.CustomerRepository;
import com.patternknife.securityhelper.oauth2.client.domain.customer.entity.Customer;

import com.patternknife.securityhelper.oauth2.client.domain.customer.entity.QCustomer;
import com.patternknife.securityhelper.oauth2.client.domain.customer.entity.QCustomerRole;
import com.patternknife.securityhelper.oauth2.client.domain.role.entity.QRole;
import com.querydsl.jpa.impl.JPAQueryFactory;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.jpa.repository.support.QuerydslRepositorySupport;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collection;


@Service
public class CustomerDetailsService extends QuerydslRepositorySupport implements UserDetailsService {

    private final JPAQueryFactory jpaQueryFactory;

    private final CustomerRepository customerRepository;

    private EntityManager entityManager;

    public CustomerDetailsService (CustomerRepository customerRepository,
                       @Qualifier("authJpaQueryFactory") JPAQueryFactory jpaQueryFactory) {
        super(Customer.class);
        this.customerRepository = customerRepository;
        this.jpaQueryFactory = jpaQueryFactory;
    }

    @Override
    @PersistenceContext(unitName = "commonEntityManager")
    public void setEntityManager(EntityManager entityManager) {
        super.setEntityManager(entityManager);
        this.entityManager = entityManager;
    }

    /*
    *   Here, I return an instance of AccessTokenUserInfo, which implements both UserDetails and OAuth2AuthenticatedPrincipal.
    *   You can understand the reasoning behind this by reviewing AccessTokenUserInfoResolver and CustomResourceServerTokenIntrospector.
    * */
    @Override
    public UserDetails loadUserByUsername(String username) {

        Customer customer = customerRepository.findByIdName(username).orElseThrow(() -> new UsernameNotFoundException("Customer (ID : \"" + username + "\") NOT Found"));
        if(customer.getDeletedAt() != null){
            if(customer.getDeleteAdminId() == null) {
                if (customer.getOneWeekAfterDeletedAsString() != null) {
                    throw new UserDeletedException("As a deleted account, re-registration is not possible until " + customer.getOneWeekAfterDeletedAsString() + ".");
                } else {
                    throw new UserDeletedException("This is a deleted account.");
                }
            }else{
                throw new UserDeletedException("Suspended by Admin.");
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


    private KnifeUserInfo<CustomizedUserInfo> buildCustomerForAuthentication(Customer customer, Collection<? extends GrantedAuthority> authorities) {
        String customername = customer.getIdName();
        String password = customer.getPassword() != null ? customer.getPassword().getValue() : "";
        boolean enabled = true;
        boolean accountNonExpired = true;
        boolean credentialsNonExpired = true;
        boolean accountNonLocked = true;

        KnifeUserInfo<CustomizedUserInfo> authCustomer = new KnifeUserInfo<>(customername, password, enabled, accountNonExpired, credentialsNonExpired,
                accountNonLocked, authorities);

        authCustomer.setCustomizedUserInfo(new CustomizedUserInfo(customer));

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