package com.patternhelloworld.securityhelper.oauth2.client.domain.customer.dao;

import com.patternhelloworld.securityhelper.oauth2.client.config.database.CommonQuerydslRepositorySupport;
import com.patternhelloworld.securityhelper.oauth2.client.config.response.error.exception.data.ResourceNotFoundException;
import com.patternhelloworld.securityhelper.oauth2.client.domain.customer.dto.CustomerResDTO;
import com.patternhelloworld.securityhelper.oauth2.client.domain.customer.entity.Customer;
import com.patternhelloworld.securityhelper.oauth2.client.domain.admin.dao.AdminRepositorySupport;
import com.patternhelloworld.securityhelper.oauth2.client.domain.admin.entity.Admin;
import com.patternhelloworld.securityhelper.oauth2.client.domain.customer.dto.CustomerReqDTO;
import com.querydsl.jpa.impl.JPAQueryFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;


@Repository
public class CustomerRepositorySupport extends CommonQuerydslRepositorySupport {

    private final JPAQueryFactory jpaQueryFactory;

    private final CustomerRepository customerRepository;
    private final AdminRepositorySupport adminRepositorySupport;

    private final String dbDialect;

    public CustomerRepositorySupport(@Qualifier("authJpaQueryFactory") JPAQueryFactory jpaQueryFactory, CustomerRepository customerRepository,
                                     AdminRepositorySupport adminRepositorySupport,
                                     @Value("${spring.jpa.properties.hibernate.dialect}") String dbDialect) {

        super(Customer.class);
        this.customerRepository = customerRepository;
        this.adminRepositorySupport = adminRepositorySupport;
        this.jpaQueryFactory = jpaQueryFactory;
        this.dbDialect = dbDialect;
    }


    public Customer findById(Long id) throws ResourceNotFoundException {
        return customerRepository.findById(id).orElseThrow(() -> new ResourceNotFoundException("Couldn't find the customer :: " + id));
    }



    public void deleteOne(Long id, Long adminId) {

        Customer customer = findById(id);
        customer.setDeletedAt(LocalDateTime.now());

        Admin admin = adminRepositorySupport.findById(adminId);
        customer.setDeleteAdmin(admin);
    }


    public void restoreOne(Long id) {

        Customer customer = findById(id);

        customer.setDeletedAt(null);
        customer.setDeleteAdmin(null);

    }



    public Customer createOne(Customer customer) {
        return customerRepository.save(customer);
    }

    @Transactional(value = "commonTransactionManager", rollbackFor = Exception.class)
    public CustomerResDTO.Id updateOne(Long id, CustomerReqDTO.Update dto) {

        final Customer customer = customerRepository.findById(id).orElseThrow(() -> new ResourceNotFoundException("Couldn't find the customer ID : '" + id));

        customer.updateCustomer(dto);


        return new CustomerResDTO.Id(customer);
    }


    @Transactional(value = "commonTransactionManager", rollbackFor = Exception.class)
    public Customer createNonSocialUser(CustomerReqDTO.Create create) {

        return customerRepository.save(create.toEntity());

    }

}
