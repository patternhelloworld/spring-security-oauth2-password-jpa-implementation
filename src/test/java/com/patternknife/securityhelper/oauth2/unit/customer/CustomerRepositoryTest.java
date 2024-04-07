package com.patternknife.securityhelper.oauth2.unit.customer;

import com.patternknife.securityhelper.oauth2.domain.customer.dao.CustomerRepository;
import com.patternknife.securityhelper.oauth2.domain.customer.entity.Customer;
import com.patternknife.securityhelper.oauth2.domain.customer.entity.QCustomer;


import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

;

// 의도적으로 DB 조회하게 하기 위해 제외
//@DataJpaTest
@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class  CustomerRepositoryTest {

    @Autowired
    private CustomerRepository customerRepository;

    private final QCustomer qCustomer = QCustomer.customer;

    @Test
    public void findByIdName_test() {
        final String idName = "cicd@test.com";
        final Customer customer = customerRepository.findByIdName(idName).get();
        assertThat(customer.getIdName()).isEqualTo(idName);
    }

    @Test
    public void findByIdName_notFound_test() {
        final String nonexistentEmail = "nonexistent@test.com";
        final Optional<Customer> optionalCustomer = customerRepository.findByIdName(nonexistentEmail);
        assertThat(optionalCustomer.isPresent()).isFalse();
    }
/*
    @Test
    public void findById_test() {
        final Optional<Customer> optionalCustomer = customerRepository.findById(1L);
        final Customer customer = optionalCustomer.get();
        assertThat(customer.getId()).isEqualTo(1L);
    }*/

/*    @Test
    public void isExistedEmail_test() {
        final String idName = "test001@test.com";
        final boolean existsByEmail = customerRepository.existsByEmail(Email.of(email));
        assertThat(existsByEmail).isTrue();
    }

    @Test
    public void findRecentlyRegistered_test() {
        final List<Customer> customers = customerRepository.findRecentlyRegistered(10);
        assertThat(customers.size()).isLessThan(11);
    }

    @Test
    public void predicate_test_001() {
        //given
        final Predicate predicate = qCustomer.email.eq(Email.of("test001@test.com"));

        //when
        final boolean exists = customerRepository.exists(predicate);

        //then
        assertThat(exists).isTrue();
    }

    @Test
    public void predicate_test_002() {
        //given
        final Predicate predicate = qCustomer.firstName.eq("test");

        //when
        final boolean exists = customerRepository.exists(predicate);

        //then
        assertThat(exists).isFalse();
    }

    @Test
    public void predicate_test_003() {
        //given
        final Predicate predicate = qCustomer.email.value.like("test%");

        //when
        final long count = customerRepository.count(predicate);

        //then
        assertThat(count).isGreaterThan(1);
    }*/


}