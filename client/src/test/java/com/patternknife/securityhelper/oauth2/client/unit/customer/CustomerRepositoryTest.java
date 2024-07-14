package com.patternknife.securityhelper.oauth2.client.unit.customer;

import com.patternknife.securityhelper.oauth2.client.domain.customer.dao.CustomerRepository;
import com.patternknife.securityhelper.oauth2.client.domain.customer.entity.Customer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;


//@DataJpaTest
@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class  CustomerRepositoryTest {

    @Autowired
    private CustomerRepository customerRepository;

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

}